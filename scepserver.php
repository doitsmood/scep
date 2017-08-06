<?php

$caCertDER = './ca/rootCA.der';
$caKeyPEM = file_get_contents('./ca/rootCA.key');
$caCertPEM = file_get_contents('./ca/rootCA.pem');
$extensions = './ca/extensions.conf';
$serial = './ca/rootCA.srl';

require 'scepHelperclass.php';
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

    list($clientCert,$csrDer) = $scep->unpack(file_get_contents('php://input'), $caCertPEM, $caKeyPEM);
    $signedCert = $scep->signCsr($csrDer, $caCertPEM, $caKeyPEM, $extensions, $serial, 25);
    $degen = $scep->createDegen($signedCert);
    $response = $scep->pack($degen, $clientCert, $caCertPEM, $caKeyPEM);
    
    echo $response;
}
 ?>