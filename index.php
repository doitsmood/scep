<?php

$rootCertDer = 'ca/rootCA.der';


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
        file_put_contents('pkcs7envelope', $derPKCS7Envelope);
}

function verifyPKCS7envelope($derFormatedPKCS7Envelope) {
    
}

?>
