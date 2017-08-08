<?php

$baseUrl = "https://scepenrollment.dev.ucb.com/certsrv/mscep/mscep.dll";
$signerCert = file_get_contents('clientCerts/scepsigner.pem');
$signerKey = file_get_contents('clientCerts/scepsigner.key');
$csr = file_get_contents('mickeytest1/mickey1csr');
$pkioperation = 'GET';
?>
