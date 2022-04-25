/*import {
    Session,
    getClientAuthenticationWithDependencies,
  } from "@inrupt/solid-client-authn-browser";

import { extractComponentOfWebId } from "./util";
import { fetchResource } from "./fetchresource";

const SERVER_ADDRESS = "http://localhost:3000/jesse/"
const targetFiles = [
    `${SERVER_ADDRESS}/output-10.json`,
    `${SERVER_ADDRESS}/output-100.json`,
    `${SERVER_ADDRESS}/output-1000.json`,
]

const session = new Session({
      clientAuthentication: getClientAuthenticationWithDependencies({}),
    },
    defaultLocalClientAppSessionId
);

let loggedIn = false;
*/

import View from "./frontend";
import React from "react";
import {createRoot} from 'react-dom/client';

const rootElement = document.getElementById('container');
const root = createRoot(rootElement);

root.render(<View />);