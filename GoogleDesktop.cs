using System;
using System.Collections.Generic;
using System.Net;
using Mirror;
using UnityEngine;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Newtonsoft.Json;

/*
    Authenticators: https://mirror-networking.com/docs/Components/Authenticators/
    Documentation: https://mirror-networking.com/docs/Guides/Authentication.html
    API Reference: https://mirror-networking.com/docs/api/Mirror.NetworkAuthenticator.html
    Special Thanks: https://github.com/googlesamples/oauth-apps-for-windows
*/

namespace Core.Authentication
{
    public class GoogleDesktop : NetworkAuthenticator
    {
        [Header("Google Authentication Settings")]
        [Space(20f)]
        public string webAppId = "<Enter your Web App ID>";
        public string clientSecret = "<Enter your client secret>";
        public string provider = "Google";
        public string authorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
        
        [Header("Scopes")]
        public List<string> googleScopes = new List<string>();
        
        private string _appId = "";
        private string _authorizationEndpoint = "";
        private string _clientSecret = "";
        private string _state = "";
        private string _scope = "";
        private string _codeChallenge = "";
        private string _codeChallengeMethod = "";
        private string _codeVerifier = "";
        private string _redirectUri = "";
        
        public enum AuthenticationResponseCode
        {
            ValidCode = 201,
            Success = 202,
            Failed = 401
        }

        #region Messages
        /// <summary>
        /// The authentication request message that gets sent from the client to the server. We send the user's information
        /// to the server for login, as well as for seamlessly creating new accounts.
        /// </summary>
        public struct AuthRequestMessage : NetworkMessage
        {
            public string oAuthCode;
            public string authority;

            public AuthRequestMessage(string oAuthCode, string authority)
            {
                this.oAuthCode = oAuthCode;
                this.authority = authority;
            }
        }

        /// <summary>
        /// The authentication response from the server to the client, here we just want to let the client know if their
        /// authentication was successful or not.
        /// </summary>
        public struct AuthResponseMessage : NetworkMessage
        {
            public AuthenticationResponseCode responseCode;
            public string message;

            public AuthResponseMessage(AuthenticationResponseCode responseCode, string message)
            {
                this.responseCode = responseCode;
                this.message = message;
            }
        }

        #endregion

        #region Server
        
        /// <summary>
        /// Called on server from StartServer to initialize the Authenticator
        /// <para>Server message handlers should be registered in this method.</para>
        /// </summary>
        public override void OnStartServer()
        {
            // register a handler for the authentication request we expect from client
            NetworkServer.RegisterHandler<AuthRequestMessage>(OnAuthRequestMessage, false);
        }

        /// <summary>
        /// Called on server from OnServerAuthenticateInternal when a client needs to authenticate
        /// </summary>
        /// <param name="conn">Connection to client.</param>
        public override void OnServerAuthenticate(NetworkConnection conn) { }

        /// <summary>
        /// Called on server when the client's AuthRequestMessage arrives
        /// </summary>
        /// <param name="conn">Connection to client.</param>
        /// <param name="msg">The message payload</param>
        public async void OnAuthRequestMessage(NetworkConnection conn, AuthRequestMessage msg)
        {
#if UNITY_STANDALONE_WIN
            Debug.Log($"[Authentication][Server] Server received authentication request from {conn.address} " +
                      $"with {msg.authority.ToString()} as the authentication provider.");

            if (msg.authority == "Google")
            {
                Debug.Log($"AUTHCODE:{msg.oAuthCode}");
                var exchange = await PerformCodeExchange(msg.oAuthCode, msg.authority);
                var response = await exchange;

                if (response.StartsWith("SUCCESS"))
                {
                    response = response.Replace("SUCCESS", "");
                
                    var json = response;
                    var values = JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
                    var message = $"Authentication Successful";
                    var UUID = "invalid_uuid";
                    values?.TryGetValue("sub", out UUID);

                    if (UUID == "invalid_uuid")
                    {
                        Debug.Log("[Authentication][Server] Failed to retrieve player UUID, invalidating login request");
                        message = "Authentication Invalidated: Failed to retrieve the user's UUID from the authentication process.";
                        AuthResponseMessage invalidatedResponse = new AuthResponseMessage(AuthenticationResponseCode.Failed, message);
                        conn.Send(invalidatedResponse);
                        return;
                    }

                    if (values != null)
                        foreach (var value in values)
                        {
                            Debug.Log($"{value}");
                        }

                    AuthResponseMessage authResponseMessage = new AuthResponseMessage(AuthenticationResponseCode.Success, message);
                    conn.Send(authResponseMessage);

                    conn.authenticationData = UUID;
                    ServerAccept(conn);
                }

                if (response.StartsWith("FAILED"))
                {
                    response = response.Replace("FAILED", "");
                
                    var json = response;
                    var values = JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
                    var message = $"Authentication Failed: Unknown Error";
                    var error = "";
                    var details = "";
                    values?.TryGetValue("error", out error);
                    values?.TryGetValue("error_description", out details);

                    if ((error + details).Length > 0) message = $"Authentication Failed: {details} (Error Code:{error})";
                
                    AuthResponseMessage authResponseMessage = new AuthResponseMessage(AuthenticationResponseCode.Failed, message);
                    conn.Send(authResponseMessage);
                
                    // Reject the unsuccessful authentication attempt.
                    ServerReject(conn);
                }
            }
#endif
        }
        
                /// <summary>
        /// Exchanges the authentication code for an authentication token which can be used to retrieve the user's data
        /// from the identity provider.
        /// </summary>
        /// <param name="code"> The authentication code that the user sent to the server.</param>
        /// <param name="authority"> The authority provider for this authentication.</param>
        /// <returns></returns>
        private async Task<Task<string>> PerformCodeExchange(string code, string authority)
        {
            Debug.Log("[Authentication][Server] Exchanging code for tokens with the authentication provider.");

            if (authority == "Google")
            {
                // Build the token request uri and body.
                string tokenRequestURI = "https://oauth2.googleapis.com/token"; //https://www.googleapis.com/oauth2/v4/token
                string tokenRequestBody =
                    $"code={code}&" +
                    $"redirect_uri={Uri.EscapeDataString(_redirectUri)}&" +
                    $"client_id={_appId}&" +
                    $"response_type=code&" + 
                    $"code_verifier={_codeVerifier}&" +
                    $"client_secret={_clientSecret}&" +
                    $"scope=&" +
                    $"grant_type=authorization_code";
                
                Debug.Log(tokenRequestBody);

                // Send the token request to the authority provider.
                HttpWebRequest tokenRequest = (HttpWebRequest) WebRequest.Create(tokenRequestURI);
                tokenRequest.Method = "POST";
                tokenRequest.ContentType = "application/x-www-form-urlencoded";
                tokenRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
                byte[] byteVersion = Encoding.ASCII.GetBytes(tokenRequestBody);
                tokenRequest.ContentLength = byteVersion.Length;
                Stream stream = tokenRequest.GetRequestStream();
                await stream.WriteAsync(byteVersion, 0, byteVersion.Length);
                stream.Close();

                try
                {
                    // Try to read the response from the authority provider.
                    WebResponse tokenResponse = await tokenRequest.GetResponseAsync();
                    using (StreamReader reader = new StreamReader(tokenResponse.GetResponseStream()))
                    {
                        // Try to read the response body.
                        string responseText = await reader.ReadToEndAsync();

                        // Convert the response body to a dictionary.
                        Dictionary<string, string> tokenEndpointDecoded = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseText);

                        // Sanity check the token endpoint dictionary.
                        if (tokenEndpointDecoded != null)
                        {
                            string accessToken = tokenEndpointDecoded["access_token"];
                            return GetUserInfoFromProvider(accessToken, authority);
                        }
                        
                        return Task.Factory.StartNew(() => "FAILED{\"error\": \"null_token_endpoint\",\"error_description\": " +
                                                           "\"The token endpoint was null.\"}");
                    }
                }
                catch (WebException ex)
                {
                    if (ex.Status == WebExceptionStatus.ProtocolError)
                    {
                        if (ex.Response is HttpWebResponse response)
                        {
                            Debug.Log("HTTP: " + response.StatusCode + response.StatusDescription + response.Method);
                            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                            {
                                // reads response body
                                string responseText = await reader.ReadToEndAsync();
                                return Task.Factory.StartNew(() => "FAILED" + responseText);
                            }
                        }
                    }

                    return Task.Factory.StartNew(() => "FAILED{\"error\": \"web_exception\",\"error_description\": " +
                                                       "\"Something went wrong trying to get a response from the authentication provider.\"}");
                }
            }
            
            return Task.Factory.StartNew(() => "FAILED{\"error\": \"invalid_authority\",\"error_description\": " +
                                               "\"Client provided authentication using an invalid authority.\"}");
        }

        private async Task<string> GetUserInfoFromProvider(string accessToken, string authority)
        {
            Debug.Log("[Authentication][Server] Retrieving user information from the authentication provider.");

            if (authority == "Google")
            {
                // Create the user info request uri.
                string userinfoRequestURI = "https://www.googleapis.com/oauth2/v3/userinfo";

                // Send the request to the authority provider.
                HttpWebRequest userinfoRequest = (HttpWebRequest) WebRequest.Create(userinfoRequestURI);
                userinfoRequest.Method = "GET";
                userinfoRequest.Headers.Add(string.Format("Authorization: Bearer {0}", accessToken));
                userinfoRequest.ContentType = "application/x-www-form-urlencoded";
                userinfoRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

                // Get the response from the authority provider.
                var userinfoResponse = await userinfoRequest.GetResponseAsync();
                using (var userinfoResponseReader = new StreamReader(userinfoResponse.GetResponseStream()))
                {
                    // Read the response body and send it back upstream.
                    string userinfoResponseText = await userinfoResponseReader.ReadToEndAsync();
                    return "SUCCESS" + userinfoResponseText;
                }
            }
            
            // Return an error if the authority provider is invalid or not implemented.
            return "FAILED{\"error\": \"invalid_authority\",\"error_description\": \"Client provided authentication using an invalid authority.\"}";
        }
        
        #endregion

        #region Client

        /// <summary>
        /// Called on client from StartClient to initialize the Authenticator
        /// <para>Client message handlers should be registered in this method.</para>
        /// </summary>
        public override void OnStartClient()
        {
            // register a handler for the authentication response we expect from server
            NetworkClient.RegisterHandler<AuthResponseMessage>(OnAuthResponseMessage, false);
        }

        /// <summary>
        /// Called on client from OnClientAuthenticateInternal when a client needs to authenticate
        /// </summary>
        /// <param name="conn">Connection of the client.</param>
        public override void OnClientAuthenticate(NetworkConnection conn)
        {
            SendAuthRequestMessage(conn);
        }
        

        /// <summary>
        /// Called on client when the server's AuthResponseMessage arrives
        /// </summary>
        /// <param name="conn">Connection to client.</param>
        /// <param name="msg">The message payload</param>
        public void OnAuthResponseMessage(AuthResponseMessage msg)
        {
            Debug.Log($"[Authentication][ServerToClient] Authentication Status: {msg.responseCode.ToString()}\n" +
                      $"{msg.message}");

            if (msg.responseCode == AuthenticationResponseCode.Success)
            {
                ClientAccept(NetworkClient.connection);
            }

            if (msg.responseCode == AuthenticationResponseCode.Failed)
            {
                ClientReject(NetworkClient.connection);
                Debug.LogError(msg.message);
            }

        }

        
        /// <summary>
        /// A Task containing the OAuth Authentication Logic
        /// </summary>
        /// <param name="conn"></param>
        /// <returns></returns>
        public async Task<AuthenticationResponseCode> SendAuthRequestMessage(NetworkConnection conn)
        {
            // Configures all of the variables required for authentication based on the selected authentication provider.
            InitializeAuthenticationProvider();

            var code = "";
            
            #region Windows Authorization
            #if UNITY_STANDALONE_WIN
            // Get an authorization code using an authentication flow that supports Windows.
            code = await GetAuthorizationCodeWindows();
            #endif
            #endregion

            // Notify the user that their authentication code was successfully retrieved from the authentication provider.
            Debug.Log("[Authentication][Client] Successfully received authentication code from the authentication provider.");
            Debug.Log("[Authentication][ClientToServer] Sending authentication request to game server.");
            
            // Send the Authentication Request message to the server, providing the encrypted authentication key, and 
            // the authentication provider of the key.
            AuthRequestMessage authRequestMessage = new AuthRequestMessage(code, provider);
            NetworkClient.Send(authRequestMessage);
            
            return AuthenticationResponseCode.ValidCode;
        }
        
        /// <summary>
        /// Gets an OAuth Authorization Code for the using a flow that is compatible with Windows. 
        /// </summary>
        /// <returns> An OAuth authorization code. </returns>
        private async Task<string> GetAuthorizationCodeWindows()
        {
            switch (provider)
            {
                case "Google":
                    // Start an HTTP listener server, that we use to listen for the user's authentication response.
                    var http = StartHttpListener();

                    // Creates the OAuth 2.0 authorization request based on our selected OAuth provider.
                    var authorizationRequest = CreateAuthorizationRequest();

                    // Opens request in the browser.
                    Application.OpenURL(authorizationRequest);
            
                    // Await the user's login, and pause this thread until we have the authentication context.
                    var context = await http.GetContextAsync();

                    // Sends an HTTP response to the browser.
                    var response = context.Response;
            
                    // Load an HTML response page for the user to notify them to switch back to the application if they haven't
                    // automatically been switched.
                    GenerateResponsePage(response, http);

                    // Checks the user's authentication response for any errors.
                    if (context.Request.QueryString.Get("error") != null)
                    {
                        Debug.LogError($"[Authentication][Client] OAuth authorization error: {context.Request.QueryString.Get("error")}.");
                        return $"FAILED_AUTHORIZATION_ERROR ({context.Request.QueryString.Get("error")}";
                    }
            
                    if (context.Request.QueryString.Get("code") == null
                        || context.Request.QueryString.Get("state") == null)
                    {
                        Debug.LogError("[Authentication][Client] [Authentication][Client] Malformed authorization response. " + context.Request.QueryString);
                        return "FAILED_MALFORMED_AUTHORIZATION_RESPONSE";
                    }

                    // Extract the code from the authentication response.
                    var code = context.Request.QueryString.Get("code");
                    var incomingState = context.Request.QueryString.Get("state");

                    // Compares the received state to the expected value, to ensure that
                    // this app made the request which resulted in authorization.
                    if (incomingState != _state)
                    {
                        Debug.LogError($"[Authentication][Client] Received request with invalid state ({incomingState})");
                        return "FAILED_INVALID_STATE";
                    }

                    return code;
                    
                default:
                    return "FAILED_INVALID_AUTHENTICATION_PROVIDER";
            }
        }

        private static void GenerateResponsePage(HttpListenerResponse response, HttpListener http)
        {
            string responseString = $"<html>" +
                                    $"<head>" +
                                    $"<meta http-equiv='refresh' content='10;url=https://google.com'>" +
                                    $"</head>" +
                                    $"<body>Authentication complete, please return to the game.</body>" +
                                    $"</html>";

            var buffer = System.Text.Encoding.UTF8.GetBytes(responseString);
            response.ContentLength64 = buffer.Length;
            var responseOutput = response.OutputStream;
            Task responseTask = responseOutput.WriteAsync(buffer, 0, buffer.Length).ContinueWith((task) =>
            {
                responseOutput.Close();
                http.Stop();
                Debug.Log("[Authentication][Client] HTTP listen server stopped successfully.");
            });
        }

        private string CreateAuthorizationRequest()
        {
            string authorizationRequest = "";

            if (provider == "Google")
                authorizationRequest = $"{_authorizationEndpoint}?" +
                                       $"response_type=code&" +
                                       $"scope={_scope}&" +
                                       $"redirect_uri={_redirectUri}&" +
                                       $"client_id={_appId}&" +
                                       $"state={_state}&" +
                                       $"code_challenge={_codeChallenge}&" +
                                       $"code_challenge_method={_codeChallengeMethod}";
            return authorizationRequest;
        }

        private HttpListener StartHttpListener()
        {
            // Creates a redirect uri using the loopback adapter and an unused port.
            _redirectUri = $"http://localhost:{GetRandomUnusedPort()}/";

            // Creates an HttpListener to listen for our authentication response redirect.
            var http = new HttpListener();
            http.Prefixes.Add(_redirectUri);
            http.Start();
            Debug.Log("[Authentication][Client] Successfully started listening for authentication loopback using HTTPListener.");
            return http;
        }

        private void InitializeAuthenticationProvider()
        {
            if (provider == "Google")
            {
                _appId = webAppId;
                _authorizationEndpoint = authorizationEndpoint;
                _state = GetRandomDataBase64URL(32);
                _codeVerifier = GetRandomDataBase64URL(32);
                _codeChallenge = GetBase64URLEncodeWithoutPadding(EncryptSha256(_codeVerifier));
                _codeChallengeMethod = "S256";
                _clientSecret = clientSecret;
                _scope = googleScopes.Aggregate(_scope, (current, googleScope) => current + (googleScope + "%20"));
            }
        }
        
        /// <summary>
        /// Returns URI-safe data with a given input length.
        /// </summary>
        /// <param name="length">Input length (nb. output will be longer)</param>
        /// <returns></returns>
        private static string GetRandomDataBase64URL(uint length)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[length];
            rng.GetBytes(bytes);
            return GetBase64URLEncodeWithoutPadding(bytes);
        }

        
        /// <summary>
        /// TcpListener will find a random un-used port to listen on if you bind to port 0.
        /// </summary>
        /// <returns> Returns a random unused port.</returns>
        private static int GetRandomUnusedPort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }
        
        /// <summary>
        /// Base64url no-padding encodes the given input buffer.
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        private static string GetBase64URLEncodeWithoutPadding(byte[] buffer)
        {
            string base64 = Convert.ToBase64String(buffer);

            // Converts base64 to base64url.
            base64 = base64.Replace("+", "-");
            base64 = base64.Replace("/", "_");
            // Strips padding.
            base64 = base64.Replace("=", "");

            return base64;
        }
        
        /// <summary>
        /// Returns the SHA256 hash of the input string.
        /// </summary>
        /// <param name="inputStirng"></param>
        /// <returns></returns>
        private static byte[] EncryptSha256(string inputStirng)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(inputStirng);
            SHA256Managed sha256 = new SHA256Managed();
            return sha256.ComputeHash(bytes);
        }
        #endregion
    }
}
