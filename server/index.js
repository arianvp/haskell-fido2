function base64Decode(str) {
  // Convert base64url to the base64 dialect understood by atob,
  // then convert the resulting string to an ArrayBuffer.
  let padded;
  if (str.length % 4 === 0) padded = str;
  if (str.length % 4 === 2) padded = str + "==";
  if (str.length % 4 === 3) padded = str + "=";
  let base64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

function base64Encode(buffer) {
  // We get an ArrayBuffer, but btoa expects a string (with only code points in
  // the range 0-255). I expected that we could do
  //
  //   btoa(new TextDecoder("latin1").decode(buffer))
  //
  // but then btoa complains that the input contains characters outside of the
  // Latin-1 range! So instead we manually map each byte with fromCharCode.
  const binaryString = Array.from(new Uint8Array(buffer), b => String.fromCharCode(b)).join("");

  // Encode the buffer in the base64 dialect returned by btoa,
  // then convert that to base64url that is required by the spec.
  return btoa(binaryString).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function deepBase64Encode(obj) {
  if (obj instanceof ArrayBuffer) {
    return base64Encode(obj);
  }
  if (obj instanceof Array) {
    return obj.map(deepBase64Encode);
  }
  if (obj instanceof Object) {
    let result = {};
    for (key in obj) {
      if (!(obj[key] instanceof Function)) {
        result[key] = deepBase64Encode(obj[key]);
      }
    }
    return result;
  }
  return obj;
}

const SERVER = "http://localhost:8080";
window.addEventListener("load", () => {
  const registerForm = document.getElementById("registerForm");
  registerForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const response = await fetch(`${SERVER}/register/begin`, { credentials: "include" });
    const params = await response.json();

    console.log("params", params);

    const publicKey = {
      rp: params.rp,
      challenge: base64Decode(params.challenge),
      pubKeyCredParams: params.pubKeyCredParams,
      user: {
        name: "john.doe",
        displayName: "John Doe",
        id: base64Decode(params.user.id),
      },
      authenticatorSelection: params.authenticatorSelection,
    };

    const credentialCreationOptions = { publicKey };
    const credential = await navigator.credentials.create(credentialCreationOptions);
    console.log("credential", credential);

    const result = await fetch(`${SERVER}/register/complete`, {
      method: "POST",
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(deepBase64Encode(credential)),
      credentials: "include"
    });

    console.log(await result.text());

  });
  const loginForm = document.getElementById("loginForm");
  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const response = await fetch(`${SERVER}/login/begin`, { credentials: "include" });
    const publicKey = await response.json();

    publicKey.challenge = base64Decode(publicKey.challenge);
    publicKey.allowCredentials.forEach(cred => cred.id = base64Decode(cred.id));

    const credentialRequestOptions = { publicKey };
    const credential = await navigator.credentials.get(credentialRequestOptions);

    const result = await fetch(`${SERVER}/login/complete`, {
      method: "POST",
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(deepBase64Encode(credential)),
      credentials: "include"
    });

    console.log(await result.text());

  });
});
