<?php
header("Content-Type: application/json");

require_once "DexPipeline.php";

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(["status" => "error", "message" => "Only POST allowed"]);
    exit;
}

if (!isset($_FILES['dex']) || !isset($_FILES['code'])) {
    http_response_code(400);
    echo json_encode(["status" => "error", "message" => "dex and code files required"]);
    exit;
}

try {
    $dexData  = file_get_contents($_FILES['dex']['tmp_name']);
    $codeData = file_get_contents($_FILES['code']['tmp_name']);

    if (!$dexData || !$codeData) {
        throw new Exception("Uploaded files are empty or invalid");
    }

    $dexman = new DexManipulator();
    $result = $dexman->runFullPipeline($dexData, $codeData);

    $simplifiedDex = [];
    foreach ($result['dexBuffers'] as $name => $buffer) {
        $simplifiedDex[] = [
            "fileName" => $name,
            "sizeBytes" => strlen($buffer),
            "base64" => base64_encode($buffer)
        ];
    }

    $simplifiedJsonDump = [];
    foreach ($result['jsonBuffers'] as $name => $jsonContent) {
        $simplifiedJsonDump[] = [
            "fileName" => $name,
            "sizeBytes" => strlen($jsonContent),
            "content" => json_decode($jsonContent, true)
        ];
    }

    echo json_encode([
        "status" => "success",
        "summary" => $result['summary'], 
        "patchedDex" => $simplifiedDex,
        "jsonDump" => $simplifiedJsonDump
    ], JSON_PRETTY_PRINT);

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        "status" => "error",
        "message" => $e->getMessage()
    ]);
}