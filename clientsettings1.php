<?php

$baseUrl = "http://10.0.1.18:8042/scepserver.php";
$signerCert = file_get_contents('clientCerts/scepsigner.pem');
$signerKey = file_get_contents('clientCerts/scepsigner.key');
$csr = file_get_contents('clientCerts/scep1.csr.der');

?>