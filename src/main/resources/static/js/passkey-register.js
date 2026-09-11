document
    .getElementById("registerPasskey")
    .addEventListener("click", async () => {

        const message =
            document.getElementById("message");

        try {

            /*
             * ① 登録オプションを取得
             */
            message.textContent =
                "Passkey登録情報を取得しています...";

            const optionsResponse =
                await fetch(
                    "/webauthn/register/options",
                    {
                        method: "POST",
                        headers: {
                            "Content-Type":
                                "application/json"
                        }
                    }
                );

            if (!optionsResponse.ok) {

                const errorText =
                    await optionsResponse.text();

                console.error(
                    "Options error:",
                    errorText
                );

                throw new Error(
                    "Passkey登録情報の取得に失敗しました"
                );
            }

            const options =
                await optionsResponse.json();

            console.log(
                "Registration options:",
                options
            );


            /*
             * ② Base64URL → Uint8Array
             */
            function base64UrlToUint8Array(
                base64Url
            ) {

                const padding =
                    "=".repeat(
                        (4 -
                            base64Url.length % 4
                        ) % 4
                    );

                const base64 =
                    (
                        base64Url
                        + padding
                    )
                        .replace(/-/g, "+")
                        .replace(/_/g, "/");

                const binaryString =
                    window.atob(base64);

                const bytes =
                    new Uint8Array(
                        binaryString.length
                    );

                for (
                    let i = 0;
                    i < binaryString.length;
                    i++
                ) {

                    bytes[i] =
                        binaryString.charCodeAt(i);
                }

                return bytes;
            }


            /*
             * ③ Uint8Array → Base64URL
             */
            function uint8ArrayToBase64Url(
                bytes
            ) {

                let binary = "";

                const chunkSize =
                    0x8000;

                for (
                    let i = 0;
                    i < bytes.length;
                    i += chunkSize
                ) {

                    binary +=
                        String.fromCharCode(
                            ...bytes.subarray(
                                i,
                                i + chunkSize
                            )
                        );
                }

                return window
                    .btoa(binary)
                    .replace(/\+/g, "-")
                    .replace(/\//g, "_")
                    .replace(/=+$/, "");
            }


            /*
             * ④ PublicKeyCredentialCreationOptions
             */
			const publicKey =
			    options.publicKey || options;


			/*
			 * Windows Helloを使用する
			 * Platform Authenticatorを明示的に指定
			 */
			publicKey.authenticatorSelection = {
			    authenticatorAttachment: "platform",
			    residentKey: "required",
			    userVerification: "required"
			};


            /*
             * challenge
             */
            if (publicKey.challenge) {

                publicKey.challenge =
                    base64UrlToUint8Array(
                        publicKey.challenge
                    );
            }


            /*
             * user.id
             */
            if (
                publicKey.user &&
                publicKey.user.id
            ) {

                publicKey.user.id =
                    base64UrlToUint8Array(
                        publicKey.user.id
                    );
            }


            /*
             * excludeCredentials
             */
            if (
                publicKey.excludeCredentials
            ) {

                publicKey.excludeCredentials =
                    publicKey.excludeCredentials.map(
                        credential => ({

                            ...credential,

                            id:
                                base64UrlToUint8Array(
                                    credential.id
                                )
                        })
                    );
            }


            /*
             * ⑤ Windows Helloを起動
             */
            message.textContent =
                "Windows Helloを起動しています...";


            const credential =
                await navigator.credentials.create({
                    publicKey: publicKey
                });


            if (!credential) {

                throw new Error(
                    "Passkeyの作成に失敗しました"
                );
            }


            console.log(
                "Credential:",
                credential
            );


            /*
             * ⑥ 登録結果を取得
             */
            const registrationData = {

                id:
                    credential.id,

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

                type:
                    credential.type
            };


            /*
             * ⑦ Spring Securityへ送信
             */
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


            /*
             * ⑧ 登録結果確認
             */
            if (!registerResponse.ok) {

                const errorText =
                    await registerResponse.text();

                console.error(
                    "Registration error:",
                    errorText
                );

                throw new Error(
                    "Passkey登録に失敗しました"
                );
            }


            /*
             * ⑨ 登録成功
             */
            message.textContent =
                "Passkeyの登録が完了しました。";


            /*
             * 1.5秒後にログイン画面へ
             */
            setTimeout(() => {

                window.location.href =
                    "/login";

            }, 1500);


        } catch (error) {

            console.error(
                "Passkey registration error:",
                error
            );

            message.textContent =
                error.message ||
                "Passkey登録に失敗しました。";
        }

    });
