<?php
$caCertDER = './ca/rootCA.der';
$caKeyPEM = './ca/rootCA.key';
$caCertPEM = './ca/rootCA.pem';
$extensions = './ca/extensions.conf';
$serial = './ca/rootCA.srl';

$scep = new ScepHelper();


//First step in SCEP request, client requests CA's/RA's public certificate
if ('GET' == $_SERVER['REQUEST_METHOD'] AND 'GetCACert' == $_GET['operation']) {
    header('Content-Type: application/x-x509-ca-cert');
    echo file_get_contents($caCertDER);
}

if ('GET' == $_SERVER['REQUEST_METHOD'] AND 'GetCACaps' == $_GET['operation']) {
    header('Content-Type: text/plain');
    $capabilities = array(
        'SHA-256',
        'POSTPKIOperation',
    );
    echo implode("\n", $capabilities);
}

if ('POST' == $_SERVER['REQUEST_METHOD'] AND 'PKIOperation' == $_GET['operation']) {
    header('Content-Type: application/x-pki-message');

// Create temporary workdir
    $tempWorkDir = exec("mktemp -d -t 'scepserver'");

// 
    file_put_contents($tempWorkDir . '/sceprequest.pkcs7', file_get_contents('php://input'));

// Extract the signer certificates from the request (OPTIONAL -> allows to verify if any additional certificates were included)
//exec("openssl smime -pk7out -in $tempWorkDir/sceprequest.pkcs7 -inform der -out $tempWorkDir/requestCertificates.pkcs7");
// Extract the encrypted CSR and requester-certificate (signer of the request-envelope) from the sceprequest
// We're expecting the signer to a self-signed certificate, hence the no-verify option
// We're still expecting a verification successfull to verify against tamporing
    $isValid = exec("openssl smime -verify -noverify -in $tempWorkDir/sceprequest.pkcs7 -inform der -signer $tempWorkDir/requesterCert.pem -out $tempWorkDir/encryptedCsr.der 2>&1");
    if (!"Verification successful" == $isValid) {
        cleanup($tempWorkDir);
        die("Sceprequest is not correctly signed");
    }

// The CSR was encrypted with the CA/RA public certificate which was provided in the first step of the scep request
// Use the CA/RA public and private key to decrypt it
    exec("openssl smime -decrypt -in $tempWorkDir/encryptedCsr.der -inform der -recip $caCertPEM -inkey $caKeyPEM -out $tempWorkDir/csr.der");
    exec("openssl req -in $tempWorkDir/csr.der -inform der -outform pem -out $tempWorkDir/csr.pem");
    copy("$tempWorkDir/csr.pem", 'csr.pem');

// Sign the CSR
    exec("openssl x509 -req -in $tempWorkDir/csr.pem -CA $caCertPEM -CAkey $caKeyPEM -extensions exts -extfile $extensions -days 100 -CAcreateserial -CAserial $serial -out $tempWorkDir/clientcert.pem");

// Put the sign client-certificate inside a degenerate ceritificates-only PKCS7
    exec("openssl crl2pkcs7 -nocrl -certfile $tempWorkDir/clientcert.pem -outform DER -out $tempWorkDir/degenerateCertOnly.der");

// Encrypt the degenerate-certificate-only using the requester-certificate
// Don't transfer input to text by using Binary option
    exec("openssl smime -encrypt -in $tempWorkDir/degenerateCertOnly.der -binary -outform DER -out $tempWorkDir/encryptedResponse.der $tempWorkDir/requesterCert.pem");

// Put the encrypted response in a Signed PKCS7 envelope
// Don't transfer input to text by using Binary option
// Replace smime header with pkcs7 header in footer and convert to der
    exec("openssl smime -sign -nodetach -in $tempWorkDir/encryptedResponse.der -binary -out $tempWorkDir/signedResponse.smime -signer $caCertPEM -inkey $caKeyPEM -certfile $caCertPEM");
    exec("openssl smime -pk7out -in $tempWorkDir/signedResponse.smime -out $tempWorkDir/signedResponse.p7");
    exec("openssl pkcs7 -in $tempWorkDir/signedResponse.p7 -inform pem -outform der -out $tempWorkDir/signedResponse.der");

    echo file_get_contents("$tempWorkDir/signedResponse.der");
    cleanup($tempWorkDir);
}

// Cleanup temporay workdir
function cleanup($tempWorkDir) {
    exec("rm -rf \"$tempWorkDir\"");
}

?>