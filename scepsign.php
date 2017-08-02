<?php

$derPKCS7Envelope = file_get_contents('pkcs7envelope');
$caKeyPEM = file_get_contents('./ca/rootCA.key');
$caCertPEM = file_get_contents('./ca/rootCA.pem');
echo signSCEPrequest ($derPKCS7Envelope, $caKeyPEM, $caCertPEM);


function signSCEPrequest ($derPKCS7Envelope, $caKeyPEM, $caCertPEM) {
    $tempfileCaCert = tempnam('./temp', 'cacer');
    $tempfileCaKey = tempnam('./temp', 'cakey');
    $tempfileDerInput = tempnam('./temp', 'input');
    file_put_contents($tempfileCaCert, $caCertPEM);
    file_put_contents($tempfileCaKey, $caKeyPEM);
    file_put_contents($tempfileDerInput, $derPKCS7Envelope);
    
    $tempfileEncryptedCSR = tempnam('./temp', 'ecsr');
    $tempSigner = tempnam('./temp', 'signer');
    exec("openssl smime -verify -noverify -in \"$tempfileDerInput\" -inform der -out \"$tempfileEncryptedCSR\" -signer \"$tempSigner\"");
    $tempfileDerCSR = tempnam('./temp', 'csr');
    exec("openssl smime -decrypt -inkey \"$tempfileCaKey\" -recip \"$tempfileCaCert\" -inform der -in \"$tempfileEncryptedCSR\" -out \"$tempfileDerCSR\"");
    $tempfilePemCSR = tempnam('./temp', 'csrPem');
    exec("openssl req -in \"$tempfileDerCSR\" -inform der -outform pem -out \"$tempfilePemCSR\"");
    $tempClientCertDer = tempnam('./temp', 'clientDer');
    exec("openssl x509 -req -days 10 -in \"$tempfilePemCSR\" -CA \"$tempfileCaCert\" -CAkey \"$tempfileCaKey\" -CAserial ca/rootCA.srl -CAcreateserial -sha256 -outform der -out \"$tempClientCertDer\"");
    $tempEncryptedClientCert = tempnam('./temp', 'eclientDer');
    exec("openssl smime -encrypt -in \"$tempClientCertDer\" -out \"$tempEncryptedClientCert\" -outform der \"$tempSigner\"");
    $tempSignedEncryptedClientCert = tempnam('./temp', 'seclientDer');
    exec("openssl smime -sign -in \"$tempEncryptedClientCert\" -signer \"$tempfileCaCert\" -inkey \"$tempfileCaKey\" -outform der -out \"$tempSignedEncryptedClientCert\" -nodetach");
    $return = file_get_contents($tempSignedEncryptedClientCert);
    unlink($tempfileCaCert);
    unlink($tempfileCaKey);
    unlink($tempfileDerInput);
    unlink($tempfileEncryptedCSR);
    unlink($tempfileDerCSR);
    unlink($tempfilePemCSR);
    unlink($tempClientCertDer);
    unlink($tempSigner);
    unlink($tempEncryptedClientCert);
    unlink($tempSignedEncryptedClientCert);
    
    return $return;
};

function extractCSRfromSCEPrequest ($derSCEPrequest, $caKeyPEM, $caCertPEM) {
    if (!($encryptedDerSmime=verifyPKSC7Envelope($derSCEPrequest))) {
        return 'Invalid PKCS7 Envelope';
    }
    $csr = decryptSmime($encryptedDerSmime, $caKeyPEM, $caCertPEM);
    
    return $csr;
}

function verifyPKSC7Envelope($derFormattedPKCS7Envelope) {
    $tempfileInput = tempnam('./temp', 'pkcs7');
    $tempfileSigner = tempnam('./temp', 'signer');
    $tempfileContent = tempnam('./temp', 'content');
    file_put_contents($tempfileInput, $derFormattedPKCS7Envelope);
    $command = "openssl smime -verify -noverify -in \"$tempfileInput\" -inform der -signer \"$tempfileSigner\" -out \"$tempfileContent\" 2>&1";
    exec($command, $output);
    unlink($tempfileInput);
    $signerPEM = file_get_contents($tempfileSigner);
    unlink($tempfileSigner);
    $content = file_get_contents($tempfileContent);
    unlink($tempfileContent);
    if(! 'Verification successful' == $output[0]) {
        return FALSE;
    }
    return $content;
}

function decryptSmime($encryptedDerSMIME, $caKeyPEM, $caCertPEM) {
    $tempfileCaCert = tempnam('./temp', 'cacer');
    $tempfileCaKey = tempnam('./temp', 'cakey');
    $tempfileDerInput = tempnam('./temp', 'input');
    $tempfileOutput = tempnam('./temp', 'output');
    file_put_contents($tempfileCaCert, $caCertPEM);
    file_put_contents($tempfileCaKey, $caKeyPEM);
    file_put_contents($tempfileDerInput, $encryptedDerSMIME);
    $command = "openssl smime -decrypt -inkey \"$tempfileCaKey\" -recip \"$tempfileCaCert\" -inform der -in \"$tempfileDerInput\" -out \"$tempfileOutput\"";
    exec($command);
    unlink($tempfileCaCert);
    unlink($tempfileCaKey);
    unlink($tempfileDerInput);
    $output = file_get_contents($tempfileOutput);
    unlink($tempfileOutput);
    return $output;
}

?>