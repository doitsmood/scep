<?php

if (!isset($argv[1])) {
    Die('Please add client-settings file as argument\n');
}

include($argv[1]);

require 'scepHelperclass.php';
$scep = new ScepHelper();


// create curl resource 
$ch = curl_init();

// set url 
curl_setopt($ch, CURLOPT_URL, "$baseUrl?operation=GetCACert&message=SCEP%20Authority");
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
//return the transfer as a string 
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

// $output contains the output string 
$caBlob = curl_exec($ch);
$caPem = $scep->extractCAFromGetCACert($caBlob);
//var_dump($caPem);
// Fetch CA Capabilities
curl_setopt($ch, CURLOPT_URL, "$baseUrl?operation=GetCACaps&message=SCEP%20Authority");
$capabilities = curl_exec($ch);
//var_dump($capabilities);

$request = $scep->pack($csr, $caPem, $signerCert, $signerKey);

if ('POST' == $pkioperation) {
    curl_setopt($ch, CURLOPT_URL, "$baseUrl?operation=PKIOperation");
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
    curl_setopt($ch, CURLOPT_POSTFIELDS, $request);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array(
        'Content-Type: application/x-pki-message',
        'Content-Length: ' . strlen($request))
    );

    $envelopedCert = curl_exec($ch);
}

if ('GET' == $pkioperation) {
    $message = urlencode(base64_encode($request));
//    file_put_contents('sendmessage', $request);
    curl_setopt($ch, CURLOPT_URL, "$baseUrl?operation=PKIOperation&message=$message");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array(
        'Content-Type: application/x-pki-message',
            )
    );
    $envelopedCert = curl_exec($ch);
}

if (!$envelopedCert) {
    Die("Empty response\n");
}

file_put_contents('answer', $envelopedCert);

list($signer, $degen) = $scep->unpack($envelopedCert, $signerCert, $signerKey);

echo $scep->readDegen($degen);




// close curl resource to free up system resources 
curl_close($ch);
?>
