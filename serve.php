<?php
/*This file is part of SourceMod Re-Banner.
    https://github.com/Nolo001-Aha/SourceMod-ReBanner
    Please consult the Wiki page regarding this file.
*/

    //MODIFY THIS VARIABLE AND PLACE YOUR CHOSEN FINGERPRINT PATH INSIDE.
    $fingerpintFilePath = "";
    
    
    $allowedFolders = array
    ( //folders we're allowed to download from
        "materials",
        "models",
        "sound",
        "cfg",
        "maps",
        "scripts"
    );

    if(!array_key_exists("id", $_GET) || !array_key_exists("url", $_GET)) //if we didn't get both url and id params, die
    {
        http_response_code(404);
        die();        
    }

    $requestedFile = $_GET['url']; // entry in the downloadtable that client requests off fastdownload.
    if(isPathMalicious($requestedFile)) //if the path is malicious, die
    {
        http_response_code(404);
        die();
    }

    $requestedFile = substr($requestedFile, 1);
    $arrrayRequestedFileFolders = explode("/", $requestedFile);
    if(!in_array($arrrayRequestedFileFolders[0], $allowedFolders)) //explode the real filepath by / and check whether the first folder is in allowed, if not - 404 and die.
    {
        http_response_code(404);
        die();
    }

    $requestedFingerprint = $_GET['id']; //fingerprint string
    if(!preg_match("/^[0-9]+$/", $requestedFingerprint)) //if id contains anything other than digits, die
    {
        http_response_code(404);
        die();
    }
	
    ini_set('memory_limit', '250M'); // incase you have to read large file like some big maps， 250MB is good enough
	
    if($requestedFile === $fingerpintFilePath)
        processFingerprintFile($requestedFile, $requestedFingerprint);


    if(!file_exists(getcwd()."/".$requestedFile)) //using getcwd for absolute path, IsPathMalicious should ensure that we have no path traversal
    {
        http_response_code(404);
        die();
    }

    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Disposition: attachment; filename="'.basename($requestedFile).'"');
    header('Content-Length: ' . filesize(getcwd()."/".$requestedFile));
    readfile(getcwd()."/".$requestedFile);
    die();
    function isPathMalicious($filePath) : bool
    {
        $originalFilePath = $filePath;
        // Remove any occurrences of "../" or "./" in the path
        $filePath = str_replace(array('../', './'), '', $filePath);
      
        // Replace backslashes with forward slashes
        $filePath = str_replace('\\', '/', $filePath);
      
        // Remove any characters that aren't letters, numbers, periods, hyphens, or slashes
        $filePath = preg_replace('/[^a-zA-Z0-9.-_\/]/', '', $filePath);
      
        // Make sure the path starts with a slash
        if ($filePath[0] !== '/') {
          $filePath = '/' . $filePath;
        }
        return $originalFilePath === $filePath ? false : true;
    }
    function processFingerprintFile($filePath, $fingerprintValue)
    {
        $finalFile = getcwd()."/".$filePath;
        $directoryPath = dirname($finalFile);
        if(!file_exists($directoryPath))
            mkdir($directoryPath, 0777, true);

        file_put_contents($finalFile, $fingerprintValue);
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Disposition: attachment; filename="'.basename($finalFile).'"');
        header('Content-Length: ' . filesize($finalFile));
        readfile($finalFile);
            
        die();
    }
?>
