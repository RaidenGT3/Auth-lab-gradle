document
    .getElementById("registerPasskey")
    .addEventListener("click", async () => {

        const message = document.getElementById("message");

        try {
            message.textContent =
                "Passkey登録情報を取得しています...";

            // ---------------------------------
            // 1. 登録用オプションを取得
            // ---------------------------------
            const optionsResponse = await fetch(
                "/webauthn/register/options",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    }
                }
            );

            if (!optionsResponse.ok) {
                throw new Error(
                    "Passkey登録情報の取得に失敗しました"
                );
            }

            const options = await optionsResponse.json();

            // Spring Securityから返された
            // PublicKeyCredentialCreationOptions
            const publicKey = options.publicKey || options;

            // ---------------------------------
            // Base64URL → Uint8Array
            // ---------------------------------
            function base64UrlToUint8Array(base64Url) {

                const padding =
                    "=".repeat((4 - base64Url.length % 4) % 4);

                const base64 =
                    (base64Url + padding)
                        .replace(/-/g, "+")
                        .replace(/_/g, "/");

                const binary =
                    atob(base64);

                return Uint8Array.from(
                    binary,
                    character => character.charCodeAt(0)
                );
            }

            // ---------------------------------
            // 2. WebAuthn用のデータを変換
            // ---------------------------------
            if (publicKey.challenge) {
                publicKey.challenge =
                    base64UrlToUint8Array(
                        publicKey.challenge
                    );
            }

            if (
                publicKey.user &&
                publicKey.user.id
            ) {
                publicKey.user.id =
                    base64UrlToUint8Array(
                        publicKey.user.id
                    );
            }

            if (publicKey.excludeCredentials) {

                publicKey.excludeCredentials =
                    publicKey.excludeCredentials.map(
                        credential => ({
                            ...credential,
                            id: base64UrlToUint8Array(
                                credential.id
                            )
                        })
                    );
            }

            // ---------------------------------
            // 3. Passkey作成
            // ---------------------------------
            message.textContent =
                "Passkey登録を開始しています...";

            const credential =
                await navigator.credentials.create({
                    publicKey: publicKey
                });

            if (!credential) {
                throw new Error(
                    "Passkeyの作成に失敗しました"
                );
            }

            // ---------------------------------
            // Uint8Array → Base64URL
            // ---------------------------------
            function uint8ArrayToBase64Url(bytes) {

                let binary = "";

                for (const byte of bytes) {
                    binary += String.fromCharCode(byte);
                }

                return btoa(binary)
                    .replace(/\+/g, "-")
                    .replace(/\//g, "_")
                    .replace(/=+$/, "");
            }

            // ---------------------------------
            // 4. 登録データを作成
            // ---------------------------------
            const registrationData = {

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

                    attestationObject:
                        uint8ArrayToBase64Url(
                            new Uint8Array(
                                credential.response
                                    .attestationObject
                            )
                        )
                },

                type: credential.type
            };

            // ---------------------------------
            // 5. サーバーへ登録
            // ---------------------------------
            message.textContent =
                "Passkeyをサーバーに登録しています...";

            const registerResponse =
                await fetch(
                    "/webauthn/register",
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body:
                            JSON.stringify(
                                registrationData
                            )
                    }
                );

            if (!registerResponse.ok) {

                const errorText =
                    await registerResponse.text();

                throw new Error(
                    "Passkey登録に失敗しました"
                    + (errorText
                        ? "\n" + errorText
                        : "")
                );
            }

            // ---------------------------------
            // 登録完了
            // ---------------------------------
            message.textContent =
                "Passkeyの登録が完了しました。";

            setTimeout(() => {
                window.location.href = "/login";
            }, 1500);

        } catch (error) {

            console.error(
                "Passkey登録エラー:",
                error
            );

            message.textContent =
                "Passkey登録に失敗しました: "
                + error.message;
        }
    });