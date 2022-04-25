import React, { Component } from "react";
import {
    Session,
    getClientAuthenticationWithDependencies,
  } from "@inrupt/solid-client-authn-browser";

import { identityProviderConfigUrl, extractComponentOfWebId } from "./util";
import { fetchResource, runExperiments } from "./experiments";

const loginIssuer = "http://localhost:3000/"
const defaultLocalClientAppSessionId = "my local session id";

class View extends Component {
    constructor(props) {
        super(props);
    
        const session = new Session({
            clientAuthentication: getClientAuthenticationWithDependencies({}),
        },
        defaultLocalClientAppSessionId
        );

        this.state = {
            isLoggedIn: false,
            session: session,
            sessionInfo: undefined
        }
    }

    async componentDidMount() {
        if (!this.state.isLoggedIn) {
          // Depending on which flow login uses, the response will either be "code" or "access_token".
          const authCode =
            new URL(window.location.href).searchParams.get("code") ||
            new URL(window.location.href).searchParams.get("access_token");
    
          if (authCode) {
            try {
              const sessionInfo = await this.state.session.handleIncomingRedirect(
                window.location.href
              );
    
              this.setState({
                isLoggedIn: true,
                sessionInfo: sessionInfo
              });
            } catch (error) {
              console.log(`Error attempting to handle what looks like an incoming OAuth2 redirect - could just be a user hitting the 'back' key to a previous redirect (since that previous code will no longer be valid!): ${error}`);
            }
          }
        }
    
        this.lookupIdentityProviderConfig(loginIssuer);
    }

    async lookupIdentityProviderConfig(url) {
        const idpConfigEndpoint = identityProviderConfigUrl(url);
        return window
          .fetch(idpConfigEndpoint)
          .then((response) => response.json())
          .then((result) => {
            if (result.userinfo_endpoint) {
                this.state.session
                    .fetch(result.userinfo_endpoint)
                    .then((response) => {
                    if (response.status !== 200) {
                        throw new Error(
                        `Failed to retrieve userinfo from identity provider, status: [${response.status}]`
                        );
                    }

                    return response.json();
                    })
                    .then((result) => {
                    const loggedInAs = result.sub;
                    document.getElementById(
                        "idp_userinfo_text"
                    ).innerHTML = `Logged into Identity Provider as user: [${loggedInAs}]`;
                    })
                    .catch((error) => {
                    document.getElementById(
                        "idp_userinfo_text"
                    ).innerHTML = `Not logged into Identity Provider`;
                    });
            } else {
              document.getElementById(
                "idp_userinfo_text"
              ).innerHTML = `Identity Provider doesn't provide access to currently logged-in user information`;
            }
            return result;
          })
          .catch((error) => {
            console.error(
              `It appears that [${idpConfigEndpoint}] is not a valid Identity Provider configuration endpoint: ${error}`
            );
            document.getElementById(
              "idp_userinfo_text"
            ).innerHTML = `Endpoint does appear to be a valid Identity Provider`;
    
            return undefined;
          });
      }

    htmlLogin() {
        return (
          <div>
            <div>
              &nbsp;
              <button onClick={async () => { await this.state.session.login({
                redirectUrl: document.location.href,
                oidcIssuer: loginIssuer,
                clientName: "PePSA benchmark",
              });}}>Log In</button>
            </div>
          </div>
        );
      }

    render() {
        if (!this.state.isLoggedIn)
            return (
              <div>
                <h1>PePSA Benchmark</h1>
                {this.htmlLogin()}
              </div>
            );
    
         
        else { 
            setTimeout(() => runExperiments(this.state.session), 2000)
            return (
              <div>
                <h1>
                  PePSA Benchmarking tool
                  <p></p>
                  Authenticated!
                </h1>
                <p>
                  <strong>WebID:</strong>{" "}
                  {extractComponentOfWebId(this.state.sessionInfo.webId, 0)}
                    <strong>
                      {extractComponentOfWebId(
                        this.state.sessionInfo.webId,
                        1
                      )}
                    </strong>
                  {extractComponentOfWebId(this.state.sessionInfo.webId, 2)}
                </p>
              </div>
            );
        }
        }
}

export default View;
