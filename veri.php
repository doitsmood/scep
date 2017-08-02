<?php

$derPKCS7Envelope = file_get_contents('pkcs7envelope');
$caKeyPEM = file_get_contents('./ca/rootCA.key');
$caCertPEM = file_get_contents('./ca/rootCA.pem');
echo extractCSRfromSCEPrequest ($derPKCS7Envelope, $caKeyPEM, $caCertPEM);

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