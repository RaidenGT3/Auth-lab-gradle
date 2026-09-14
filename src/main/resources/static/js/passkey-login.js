/**
 * 
 */
document
    .getElementById("loginPasskey")
    .addEventListener("click", async () => {

        const message =
            document.getElementById("message");

        try {
            // ---------------------------------
            // 1. 認証用オプションを取得
            // ---------------------------------
            message.textContent =
                "Passkey認証情報を取得しています...";

            const optionsResponse = await fetch(
                "/webauthn/authenticate/options",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    }
                }
            );

            if (!optionsResponse.ok) {
                throw new Error(
                    "Passkey認証情報の取得に失敗しました"
                );
            }

            const options =
                await optionsResponse.json();

            const publicKey =
                options.publicKey || options;

            // ---------------------------------
            // Base64URL → Uint8Array
            // ---------------------------------
            function base64UrlToUint8Array(base64Url) {

                const padding =
                    "=".repeat(
                        (4 - base64Url.length % 4) % 4
                    );

                const base64 =
                    (base64Url + padding)
                        .replace(/-/g, "+")
                        .replace(/_/g, "/");

                const binary =
                    atob(base64);

                return Uint8Array.from(
                    binary,
                    character =>
                        character.charCodeAt(0)
                );
            }

            // ---------------------------------
            // 2. Challengeを変換
            // ---------------------------------
            if (publicKey.challenge) {
                publicKey.challenge =
                    base64UrlToUint8Array(
                        publicKey.challenge
                    );
            }

            // ---------------------------------
            // 3. allowCredentialsを変換
            // ---------------------------------
            if (publicKey.allowCredentials) {

                publicKey.allowCredentials =
                    publicKey.allowCredentials.map(
                        credential => ({
                            ...credential,
                            id:
                                base64UrlToUint8Array(
                                    credential.id
                                )
                        })
                    );
            }

            // ---------------------------------
            // 4. Passkey認証開始
            // ---------------------------------
            message.textContent =
                "Passkey認証を開始しています...";

            const credential =
                await navigator.credentials.get({
                    publicKey: publicKey
                });

            if (!credential) {
                throw new Error(
                    "Passkey認証に失敗しました"
                );
            }

            // ---------------------------------
            // Uint8Array → Base64URL
            // ---------------------------------
            function uint8ArrayToBase64Url(bytes) {

                let binary = "";

                for (const byte of bytes) {
                    binary +=
                        String.fromCharCode(byte);
                }

                return btoa(binary)
                    .replace(/\+/g, "-")
                    .replace(/\//g, "_")
                    .replace(/=+$/, "");
            }

            // ---------------------------------
            // 5. 認証結果を作成
            // ---------------------------------
            const authenticationData = {

                id: credential.id,

                rawId:
                    uint8ArrayToBase64Url(
                        new Uint8Array(
                            credential.rawId
                        )
                    ),

                response: {

                    clientDataJSON:
                        uint8ArrayToBase64Url(
                            new Uint8Array(
                                credential.response
                                    .clientDataJSON
                            )
                        ),

                    authenticatorData:
                        uint8ArrayToBase64Url(
                            new Uint8Array(
                                credential.response
                                    .authenticatorData
                            )
                        ),

                    signature:
                        uint8ArrayToBase64Url(
                            new Uint8Array(
                                credential.response
                                    .signature
                            )
                        ),

                    userHandle:
                        credential.response.userHandle
                            ? uint8ArrayToBase64Url(
                                new Uint8Array(
                                    credential.response
                                        .userHandle
                                )
                            )
                            : null
                },

                type: credential.type
            };

            // ---------------------------------
            // 6. サーバーへ認証結果を送信
            // ---------------------------------
            message.textContent =
                "Passkey認証結果を確認しています...";

            const loginResponse =
                await fetch(
                    "/login/webauthn",
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body:
                            JSON.stringify(
                                authenticationData
                            )
                    }
                );

            // ---------------------------------
            // 7. ログイン結果
            // ---------------------------------
            if (!loginResponse.ok) {

                const errorText =
                    await loginResponse.text();

                throw new Error(
                    "Passkeyログインに失敗しました"
                    + (
                        errorText
                            ? "\n" + errorText
                            : ""
                    )
                );
            }

            message.textContent =
                "Passkeyログインに成功しました。";

            setTimeout(() => {
                window.location.href = "/";
            }, 1000);

        } catch (error) {

            console.error(
                "Passkeyログインエラー:",
                error
            );

            message.textContent =
                "Passkeyログインに失敗しました: "
                + error.message;
        }
    });