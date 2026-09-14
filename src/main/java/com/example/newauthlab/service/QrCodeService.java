package com.example.newauthlab.service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.springframework.stereotype.Service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

@Service
public class QrCodeService {

    /**
     * 文字列からQRコード画像を生成する
     *
     * @param text QRコードに埋め込む文字列
     * @param width QRコードの横幅
     * @param height QRコードの高さ
     * @return PNG画像のバイト配列
     */
    public byte[] generateQrCode(
            String text,
            int width,
            int height) throws WriterException, IOException {

        QRCodeWriter qrCodeWriter =
                new QRCodeWriter();

        BitMatrix bitMatrix =
                qrCodeWriter.encode(
                        text,
                        BarcodeFormat.QR_CODE,
                        width,
                        height
                );

        ByteArrayOutputStream outputStream =
                new ByteArrayOutputStream();

        MatrixToImageWriter.writeToStream(
                bitMatrix,
                "PNG",
                outputStream
        );

        return outputStream.toByteArray();
    }
}