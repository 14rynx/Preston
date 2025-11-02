import base64
import re
import time
from http import HTTPStatus
from json import JSONDecodeError
from typing import Optional, Tuple, Any, Union, Coroutine

import jwt
import asyncio
import aiohttp

from .cache import Cache


class Preston:
    """Preston class.

    This class is used to interface with the EVE Online "ESI" API.

    The __init__ method only **kwargs instead of a specific
    listing of arguments; here's the list of useful key-values:

        version                 version of the spec to load

        user_agent              user-agent to use

        client_id               app's client id

        client_secret           app's client secret

        callback_url            app's callback url

        scope                   app's scope(s)

        access_token            if supplied along with access_expiration,
                                Preston will make authenticated calls to ESI

        access_expiration       see above

        refresh_token           if supplied, Preston will use it to get new
                                access tokens; can be supplied with or without
                                access_token and access_expiration

    Args:
        kwargs: various configuration options
    """

    BASE_URL = "https://esi.evetech.net"
    SPEC_URL = BASE_URL + "/_{}/swagger.json"
    ISSUER = "https://login.eveonline.com"
    OAUTH_URL = ISSUER + "/v2/oauth"
    JWKS_URL = ISSUER + "/oauth/jwks"
    TOKEN_URL = OAUTH_URL + "/token"
    AUTHORIZE_URL = OAUTH_URL + "/authorize"
    METHODS = ["get", "post", "put", "delete"]
    OPERATION_ID_KEY = "operationId"
    VAR_REPLACE_REGEX = r"{(\w+)}"

    def __init__(self, **kwargs: Any):
        self.cache = Cache()
        self.spec = None
        self.version = kwargs.get("version", "latest")
        self.timeout = kwargs.get("timeout", 6)
        self.retries = kwargs.get("retries", 4)
        self.client_id = kwargs.get("client_id")
        self.client_secret = kwargs.get("client_secret")
        self.callback_url = kwargs.get("callback_url")

        # Allow scopes to be directly pasted from developers.eveonline.com no matter if it is one or multiple
        scope = kwargs.get("scope", "")
        if isinstance(scope, str):
            self.scope = scope
        elif isinstance(scope, list):
            self.scope = " ".join(scope)
        else:
            raise TypeError("scope must be a string or list!")

        self.access_token = kwargs.get("access_token")
        self.access_expiration = kwargs.get("access_expiration")
        self.refresh_token = kwargs.get("refresh_token")
        self.refresh_token_callback = kwargs.get("refresh_token_callback")
        self.stored_headers = []
        self._kwargs = kwargs
        self.session = None

    async def _make_session(self):
        """Async portion of initialization, to be called first in async functions"""

        if self.session is None:
            self.session = aiohttp.ClientSession()
            self.session.headers.update(
                {"User-Agent": self._kwargs.get("user_agent", ""), "Accept": "application/json"}
            )

    async def _close(self):
        if not self.session.closed:
            await self.session.close()

    def __del__(self):
        try:
            if not self.session.closed:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.ensure_future(self._close())
                else:
                    loop.run_until_complete(self._close())
        except AttributeError:
            pass

    async def _retry_request(
        self,
        requests_function: callable,
        target_url: str,
        return_metadata=False,
        **kwargs,
    ) -> Coroutine:
        """

        Tries some request with exponential backoff on server-side failures.
        And immediately raises client-side failures.
        This automatically adds a timeout to the request as well.

        Args:
            requests_function: Function to call to make the request
            target_url:        Target URL for request
            return_metadata:   Whether to return raw response or json. In this case no retries on JSONDecodeError
            **kwargs:          Additional keyword arguments for function
        Returns:
            new response
        Raises:
            aiohttp.ClientResponseError (for client-side errors)
            aiohttp.ClientConnectionError (for connection errors)
        """

        for x in range(self.retries):
            try:
                async with requests_function(target_url, **kwargs, timeout=self.timeout) as resp:
                    resp.raise_for_status()
                    if await resp.text():
                        json_data = await resp.json()
                    else:
                        json_data = None

                    if return_metadata:
                        return json_data, resp.headers, resp.url
                    return json_data

            except TimeoutError:
                pass  # Just try again

            except JSONDecodeError:
                pass  # Message was not completed. Just try again

            except aiohttp.ClientPayloadError:
                pass  # Message was not completed. Just try again

            except aiohttp.ClientResponseError as exc:
                code = exc.status
                if code in [
                    HTTPStatus.TOO_MANY_REQUESTS,
                    420,  # Enhance your calm, ESI Error limit
                ]:
                    await asyncio.sleep(int(exc.response.headers.get("X-Esi-Error-Limit-Reset", 0)))
                elif code not in [
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    HTTPStatus.BAD_GATEWAY,
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    HTTPStatus.GATEWAY_TIMEOUT,
                ]:
                    raise

            except aiohttp.ClientConnectionError:
                raise  # No internet, raise immediately without retry

            # Exponential Backoff
            await asyncio.sleep(2 ** x)

        raise aiohttp.ClientConnectionError("ESI could not complete the request.")

    def copy(self) -> "Preston":
        """Creates a copy of this Preston object.

        The returned instance is not connected to this, so you can set
        whichever headers or other data you want without impacting this instance.

        The configuration of the returned instance will match the (original)
        configuration of this instance - the kwargs are reused.

        Args:
            None

        Returns:
            new Preston instance
        """
        return Preston(**self._kwargs)

    def _get_authorization_headers(self) -> dict:
        """Constructs and returns the Authorization header for the client app.

        Args:
            None

        Returns:
            header dict for communicating with the authorization endpoints
        """
        auth = base64.encodebytes(
            bytes(f"{self.client_id}:{self.client_secret}", "latin-1")
        ).decode("latin-1")
        auth = auth.replace("\n", "").replace(" ", "")
        auth = "Basic {}".format(auth)
        headers = {"Authorization": auth}
        return headers

    async def _try_refresh_access_token(self):
        """Attempts to get a new access token using the refresh token, if needed.

        If the access token is expired and this instance has a stored refresh token,
        then the refresh token is in the API call to get a new access token. If
        successful, this instance is modified in-place with that new access token.

        Also updates the `requests` session with the new header.

        Args:
            None

        Returns:
            None
        """
        await self._make_session()

        if self.refresh_token:
            if not self.access_token or self._is_access_token_expired():
                headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                }

                data = {
                    "grant_type": "refresh_token",
                    "refresh_token": self.refresh_token,
                    "client_id": self.client_id,
                }

                response_data = await self._retry_request(
                    self.session.post,
                    self.TOKEN_URL,
                    headers=headers,
                    data=data,
                )

                self.access_token = response_data["access_token"]
                self.access_expiration = time.time() + response_data["expires_in"]
                self.refresh_token = response_data.get(
                    "refresh_token", self.refresh_token
                )
                if self.refresh_token_callback is not None:
                    await self.refresh_token_callback(self)

        if self.access_token:
            self.session.headers.update(
                {"Authorization": f"Bearer {self.access_token}"}
            )

    def _is_access_token_expired(self) -> bool:
        """Returns true if the stored access token has expired.

        Args:
            None

        Returns:
            True if the access token is expired
        """
        return time.time() > self.access_expiration

    def get_authorize_url(self, state: str = "default") -> str:
        """Constructs and returns the authorization URL.

        This is the URL that a user will have to navigate to in their browser
        and complete the login and authorization flow. Upon completion, they
        will be redirected to your app's callback URL.

        Args:
            state: state of the application

        Returns:
            URL
        """
        return (
            f"{self.AUTHORIZE_URL}?response_type=code&redirect_uri={self.callback_url}"
            f"&client_id={self.client_id}&scope={self.scope.replace(' ', '%20')}&state={state}"
        )

    async def authenticate(self, code: str) -> "Preston":
        """Authenticates using the code from the EVE SSO.

        A new Preston object is returned; this object is not modified.

        The intended usage is:

            auth = preston.authenticate('some_code_here')

        Args:
            code: SSO code

        Returns:
            new Preston, authenticated
        """
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }

        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.callback_url,
            "client_id": self.client_id,
        }

        await self._make_session()
        response_data = await self._retry_request(
            self.session.post,
            self.TOKEN_URL,
            headers=headers,
            data=data,
        )

        new_kwargs = dict(self._kwargs)
        new_kwargs["access_token"] = response_data["access_token"]
        new_kwargs["access_expiration"] = time.time() + float(
            response_data["expires_in"]
        )
        new_kwargs["refresh_token"] = response_data["refresh_token"]

        return Preston(**new_kwargs)

    async def authenticate_from_token(self, refresh_token) -> "Preston":
        """Authenticates usign a stored refresh token.

        A new Preston object is returned; this object is not modified.

        The intended usage is:

            auth = preston.authenticate('refresh_token')

        Args:
            refresh_token: currently active refresh token

        Returns:
            new Preston, authenticated
        """
        if len(refresh_token) != 24:
            raise Exception(
                "You have passed in a legacy token, these are no longer supported by CCP!"
            )

        new_kwargs = dict(self._kwargs)
        new_kwargs["refresh_token"] = refresh_token
        new_kwargs["access_token"] = None
        return Preston(**new_kwargs)

    async def _get_spec(self) -> dict:
        """Fetches the OpenAPI spec from the server.

        If the spec has already been fetched, the cached version is returned instead.

        Args:
            None

        Returns:
            OpenAPI spec data
        """
        if self.spec:
            return self.spec

        await self._make_session()
        self.spec = await self._retry_request(
            self.session.get, self.SPEC_URL.format(self.version)
        )
        return self.spec

    async def _get_path_for_op_id(self, op_id: str) -> Optional[str]:
        """Searches the spec for a path matching the operation id.

        Args:
            op_id: operation id

        Returns:
            path to the endpoint, or `None` if not found
        """
        spec = await self._get_spec()
        for path_key, path_value in spec["paths"].items():
            for method in self.METHODS:
                if method in path_value:
                    if self.OPERATION_ID_KEY in path_value[method]:
                        if path_value[method][self.OPERATION_ID_KEY] == op_id:
                            return path_key
        return None

    def _insert_vars(self, path: str, data: dict) -> tuple[str, dict]:
        """Inserts variables into the ESI URL path.

        Args:
            path: raw ESI URL path
            data: data to insert into the URL

        Returns:
            tuple of the path with variables filled, and
            and remaining, unused dict items
        """
        data = data.copy()
        while True:
            match = re.search(self.VAR_REPLACE_REGEX, path)
            if not match:
                return path, data
            replace_from = match.group(0)
            replace_with = str(data.pop(match.group(1), ""))
            path = path.replace(replace_from, replace_with)

    def _build_url(self, path: str, data: dict) -> str:
        """Build a complete URL.

        Args:
            path: raw ESI URL path
            data: data to insert into the URL

        Returns:
            url
        """
        path, query_params = self._insert_vars(path, data)
        target_url = f"{self.BASE_URL}{path}"

        return target_url

    async def whoami(self) -> dict:
        """Returns the basic information about the authenticated character.

        Obviously doesn't do anything if this Preston instance is not
        authenticated, so it returns an empty dict.

        Args:
            None

        Returns:
            character info if authenticated, otherwise an empty dict
        """

        await self._try_refresh_access_token()

        if not self.access_token:
            return {}

        try:
            # Get the JWT header to determine the key ID (kid)
            unverified_header = jwt.get_unverified_header(self.access_token)

            # Fetch the public keys (JWKS)
            async with self.session.get(self.JWKS_URL) as jwks_response:
                jwks = await jwks_response.json()

            # Find the public key with matching kid
            key = next(
                (k for k in jwks["keys"] if k["kid"] == unverified_header["kid"]), None
            )
            if not key:
                raise Exception("Unable to find appropriate public key for JWT.")

            # Convert JWKS to RSA public key
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)

            # Decode and validate JWT
            payload = jwt.decode(
                self.access_token,
                public_key,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=self.ISSUER,
                leeway=10,  # allow 10 seconds of clock skew
            )

            return {
                "character_id": payload.get("sub").split(":")[-1],
                "character_name": payload.get("name"),
                "scopes": payload.get("scp", []),
                "owner_hash": payload.get("owner"),
                "token_type": payload.get("token_type", "Character"),
            }

        except Exception as e:
            print(f"[whoami] Failed to decode/verify JWT: {e}")
            return {}

    async def get_path(self, path: str, data: dict) -> dict:
        """Queries the ESI by an endpoint URL.

        This method is not marked "private" as it _can_ be used
        by consuming code, but it's probably easier to call the
        `get_op` method instead.

        Args:
            path: raw ESI URL path
            data: data to insert into the URL

        Returns:
            ESI data
        """
        target_url = self._build_url(path, data)

        cached_data = self.cache.check(target_url)
        if cached_data:
            return cached_data
        await self._try_refresh_access_token()

        data, headers, url = await self._retry_request(
            self.session.get, target_url, return_metadata=True
        )
        self.cache.set(data, headers, url)
        self.stored_headers.insert(0, headers)
        return data

    async def get_op(self, op_id: str, **kwargs: str) -> dict:
        """Queries the ESI by looking up an operation id.

        Endpoints are cached, so calls to this method for the
        same op and args will return the data from the cache
        instead of making the API call.

        Passed kwargs will first supply parameters in the URL,
        and then unused items will be used as query params.

        Args:
            op_id: operation id
            kwargs: data to populate the endpoint's URL variables

        Returns:
            ESI data
        """
        path = await self._get_path_for_op_id(op_id)
        return await self.get_path(path, kwargs)

    async def post_path(
            self, path: str, path_data: Union[dict, None], post_data: Any
    ) -> dict:
        """Modifies the ESI by an endpoint URL.

        This method is not marked "private" as it _can_ be used
        by consuming code, but it's probably easier to call the
        `get_op` method instead.

        Args:
            path: raw ESI URL path
            path_data: data to format the path with (can be None)
            post_data: data to send to ESI

        Returns:
            ESI data
        """
        target_url = self._build_url(path, path_data)
        await self._try_refresh_access_token()
        return await self._retry_request(self.session.post, target_url, json=post_data)

    async def post_op(self, op_id: str, path_data: Union[dict, None], post_data: Any) -> dict:
        """Modifies the ESI by looking up an operation id.

        Args:
            op_id: operation id
            path_data: data to format the path with (can be None)
            post_data: data to send to ESI

        Returns:
            ESI data
        """
        path = await self._get_path_for_op_id(op_id)
        return await self.post_path(path, path_data, post_data)

    async def delete_path(self, path: str, path_data: Union[dict, None]) -> dict:
        """Deletes a resource in the ESI by an endpoint URL.

        This method is not marked "private" as it _can_ be used
        by consuming code, but it's probably easier to call the
        `delete_op` method instead.

        Args:
            path: raw ESI URL path
            path_data: data to format the path with (can be None)

        Returns:
            ESI response data
        """
        target_url = self._build_url(path, path_data)
        await self._try_refresh_access_token()
        return await self._retry_request(self.session.delete, target_url)

    async def delete_op(self, op_id: str, path_data: Union[dict, None]) -> dict:
        """Deletes a resource in the ESI by looking up an operation id.

        Args:
            op_id: operation id
            path_data: data to format the path with (can be None)

        Returns:
            ESI response data
        """
        path = await self._get_path_for_op_id(op_id)
        return await self.delete_path(path, path_data)
