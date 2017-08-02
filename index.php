<?php

$rootCertDer = 'ca/rootCA.der';
$caKeyPEM = file_get_contents('./ca/rootCA.key');
$caCertPEM = file_get_contents('./ca/rootCA.pem');

//First step in SCEP request, client requests CA's/RA's public certificate
if ('GET' == $_SERVER['REQUEST_METHOD'] AND 'GetCACert' == $_GET['operation'] ) {
	header('Content-Type: application/x-x509-ca-cert');
	echo file_get_contents($rootCertDer);
}

if ('GET' == $_SERVER['REQUEST_METHOD'] AND 'GetCACaps' == $_GET['operation'] ) {
	header('Content-Type: text/plain');
	$capabilities = array(
            'SHA-256',
            'POSTPKIOperation',
        );
        echo implode("\n", $capabilities);
}

if ('POST' == $_SERVER['REQUEST_METHOD'] AND 'PKIOperation' == $_GET['operation'] ) {
	$derPKCS7Envelope = file_get_contents('php://input');
        header('Content-Type: application/x-pki-message');
        echo signSCEPrequest ($derPKCS7Envelope, $caKeyPEM, $caCertPEM);
}

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
    $tempClientCertPem = tempnam('./temp', 'clientDer');
    exec("openssl x509 -req -days 10 -in \"$tempfilePemCSR\" -CA \"$tempfileCaCert\" -CAkey \"$tempfileCaKey\" -CAserial ca/rootCA.srl -CAcreateserial -sha256 -outform pem -out \"$tempClientCertPem\"");
    $tempDegenPKCS7 = tempnam('./temp', 'degenPKCS7');
    exec("openssl crl2pkcs7 -nocrl -certfile \"$tempClientCertPem\" -outform der -out \"$tempDegenPKCS7\" ");
    $tempEncryptedClientCert = tempnam('./temp', 'eclientDer');
    exec("openssl smime -encrypt -in \"$tempDegenPKCS7\" -out \"$tempEncryptedClientCert\" -outform der \"$tempSigner\"");
    $return = file_get_contents($tempEncryptedClientCert);
    
//    $tempSignedEncryptedClientCert = tempnam('./temp', 'seclientDer');
//    exec("openssl smime -sign -in \"$tempEncryptedClientCert\" -signer \"$tempfileCaCert\" -inkey \"$tempfileCaKey\" -outform der -out \"$tempSignedEncryptedClientCert\" -nodetach");
//    $return = file_get_contents($tempSignedEncryptedClientCert);
    unlink($tempfileCaCert);
    unlink($tempfileCaKey);
    unlink($tempfileDerInput);
    unlink($tempfileEncryptedCSR);
    unlink($tempfileDerCSR);
    unlink($tempfilePemCSR);
    unlink($tempClientCertPem);
    unlink($tempSigner);
    unlink($tempEncryptedClientCert);
//    unlink($tempSignedEncryptedClientCert);
    unlink($tempDegenPKCS7);
    
    return $return;
};

?>
