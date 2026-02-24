<?php

class DexManipulator {
    

    public function runFullPipeline($dexInput, $codeInput) {
        $start = microtime(true);
        $notes = [];
        

        $zipBuf = $this->extractEmbeddedZipFromDex($dexInput);
        $zip = new ZipArchive();
        $tempZip = tempnam(sys_get_temp_dir(), 'dex_zip');
        file_put_contents($tempZip, $zipBuf);
        $zip->open($tempZip);
        
        $extractedFiles = [];
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $stat = $zip->statIndex($i);
            if (!$stat['name'] || substr($stat['name'], -1) === '/') continue;
            $extractedFiles[] = $stat['name'];
        }

        $dexEntries = [];
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $stat = $zip->statIndex($i);
            $name = $stat['name'];
            if (preg_match('/^classes\d*\.dex$/i', $name)) {
                $dexEntries[] = $name;
            }
        }
        usort($dexEntries, [$this, 'naturalDexSort']);
        
        if (empty($dexEntries)) {
            $notes[] = "No classes*.dex found; falling back to any .dex entries";
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i);
                $name = $stat['name'];
                if (strtolower(substr($name, -4)) === '.dex') {
                    $dexEntries[] = $name;
                }
            }
            sort($dexEntries);
        }
        
        $dexBuffers = [];
        foreach ($dexEntries as $name) {
            $dexBuffers[$name] = $zip->getFromName($name);
        }

        $multi = $this->readMultiDexCode($codeInput);

        if (count($dexEntries) > $multi['dexCount']) {
            $notes[] = "Embedded ZIP has " . count($dexEntries) . " dex files, but code.bin dexCount is {$multi['dexCount']}. Only first {$multi['dexCount']} dex will be patched.";
        } else if (count($dexEntries) < $multi['dexCount']) {
            $notes[] = "code.bin dexCount is {$multi['dexCount']}, but embedded ZIP has only " . count($dexEntries) . " dex files. Only " . count($dexEntries) . " dex will be patched.";
        }
        
        $jsonFiles = [];
        $jsonBuffers = [];
        $restored = [];
        
        $patchCount = min($multi['dexCount'], count($dexEntries));
        
        for ($dexIdx = 0; $dexIdx < $patchCount; $dexIdx++) {
            $dexName = $dexEntries[$dexIdx];
            if (!isset($dexBuffers[$dexName])) continue;
            
            $dexBuf = $dexBuffers[$dexName];
            $parsed = $this->parseDex($dexBuf);
            
            $byMethodInsns = [];
            foreach ($parsed['methods'] as $m) {
                if (!empty($m['insnsOff'])) {
                    $byMethodInsns[$m['methodIdx']] = $m['insnsOff'];
                }
            }
            
            $restoredMethods = 0;
            
            $methodMeta = [];
            foreach ($parsed['methods'] as $m) {
                $methodMeta[$m['methodIdx']] = ['cls' => $this->classNameFromDescriptor($m['classDescriptor'])];
            }
            
            $classGroups = [];
            
            foreach ($multi['dexCodes'][$dexIdx]['instructions'] as $insn) {
                $off = isset($byMethodInsns[$insn['methodIndex']]) ? $byMethodInsns[$insn['methodIndex']] : null;
                if (!$off) continue;
                
                $dexBuf = $this->patchDexInsns($dexBuf, $off, $insn['data']);
                $restoredMethods++;
                
                $meta = isset($methodMeta[$insn['methodIndex']]) ? $methodMeta[$insn['methodIndex']] : null;
                $cls = $meta ? $meta['cls'] : "Unknown";
                $hexList = implode(',', array_map(function($b) {
                    return str_pad(dechex(ord($b)), 2, '0', STR_PAD_LEFT);
                }, str_split($insn['data'])));
                
                if (!isset($classGroups[$cls])) $classGroups[$cls] = [];
                $classGroups[$cls][] = ['methodId' => $insn['methodIndex'], 'code' => "[$hexList]"];
            }
            
            $dexBuf = $this->fixDexHeaders($dexBuf);
            $dexBuffers[$dexName] = $dexBuf;
            
            $restored[] = ['dexIndex' => $dexIdx, 'dexFile' => $dexName, 'restoredMethods' => $restoredMethods];
            
            $dexJson = [];
            foreach ($classGroups as $className => $methods) {
                $dexJson[] = [$className => $methods];
            }
            $jsonName = $dexName . ".json";
            $jsonFiles[] = $jsonName;
            $jsonBuffers[$jsonName] = json_encode($dexJson, JSON_PRETTY_PRINT);
        }
        
        $zip->close();
        unlink($tempZip);
        
        $elapsedSeconds = round(microtime(true) - $start, 3);
        
        $summary = [
            'extractedFiles' => $extractedFiles,
            'dexFiles' => $dexEntries,
            'jsonFiles' => $jsonFiles,
            'restored' => $restored,
            'elapsedSeconds' => $elapsedSeconds,
            'multidex' => ['version' => $multi['version'], 'dexCount' => $multi['dexCount']],
            'notes' => $notes,
        ];
        
        return ['summary' => $summary, 'dexBuffers' => $dexBuffers, 'jsonBuffers' => $jsonBuffers];
    }
    

    public function restoreDexFromCodeFile($dex, $codeBlob) {
        $multi = $this->readMultiDexCode($codeBlob);
        $parsed = $this->parseDex($dex);
        
        $jsonByClass = [];
        $patched = 0;
        $missing = 0;
        
        foreach ($parsed['methods'] as $m) {
            if (empty($m['insnsOff'])) continue;
            $code = $this->getCodeBytes($multi, $m['methodIdx']);
            if ($code === null) {
                $missing++;
                continue;
            }
            
            $dex = $this->patchDexInsns($dex, $m['insnsOff'], $code);
            $patched++;
            
            $cls = $m['classDescriptor'];
            $sig = $this->methodSig($m);
            if (!isset($jsonByClass[$cls])) $jsonByClass[$cls] = [];
            $jsonByClass[$cls][$sig] = base64_encode($code);
        }
        
        $dex = $this->fixDexHeaders($dex);
        
        return [
            'restoredDex' => $dex,
            'report' => [
                'patchedMethods' => $patched,
                'missingMethods' => $missing,
                'multidex' => [
                    'magic' => $multi['magic'],
                    'version' => $multi['version'],
                    'entryCountHeader' => $multi['entryCountHeader'],
                    'entryCountUsed' => $multi['entryCountUsed'],
                    'dataOffHeader' => $multi['dataOffHeader'],
                    'dataOffUsed' => $multi['dataOffUsed'],
                    'warnings' => $multi['warnings'],
                ],
            ],
            'jsonByClass' => $jsonByClass,
        ];
    }
    
    public function restoreDexFromEmbeddedZip($dex) {
        $zipBuf = $this->extractEmbeddedZipFromDex($dex);
        
        $zip = new ZipArchive();
        $tempZip = tempnam(sys_get_temp_dir(), 'dex_zip');
        file_put_contents($tempZip, $zipBuf);
        $zip->open($tempZip);

        $candidate = null;
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $stat = $zip->statIndex($i);
            if (substr($stat['name'], -1) === '/') continue;
            $data = $zip->getFromIndex($i);
            if (strlen($data) > 32) {
                $candidate = $data;
                break;
            }
        }
        
        $zip->close();
        unlink($tempZip);
        
        if (!$candidate) throw new Exception("No embedded zip");
        
        $multi = $this->readMultiDexCode($candidate);
        $parsed = $this->parseDex($dex);
        
        $jsonByClass = [];
        $patched = 0;
        $missing = 0;
        
        foreach ($parsed['methods'] as $m) {
            if (empty($m['insnsOff'])) continue;
            $code = $this->getCodeBytes($multi, $m['methodIdx']);
            if ($code === null) {
                $missing++;
                continue;
            }
            
            $dex = $this->patchDexInsns($dex, $m['insnsOff'], $code);
            $patched++;
            
            $cls = $m['classDescriptor'];
            $sig = $this->methodSig($m);
            if (!isset($jsonByClass[$cls])) $jsonByClass[$cls] = [];
            $jsonByClass[$cls][$sig] = base64_encode($code);
        }
        
        $dex = $this->fixDexHeaders($dex);
        
        return [
            'restoredDex' => $dex,
            'report' => ['patchedMethods' => $patched, 'missingMethods' => $missing],
            'jsonByClass' => $jsonByClass,
        ];
    }

    public function extractEmbeddedZipFromDex($dex) {
        $sig = "\x50\x4b\x03\x04";
        $idx = strpos($dex, $sig);
        if ($idx === false) throw new Exception("Embedded ZIP signature not found in DEX");
        return substr($dex, $idx);
    }

    public function readMultiDexCode($buf) {
        $off = 0;
        $len = strlen($buf);
        
        $this->ensure($buf, $off, 2, "version");
        $version = $this->readUInt16LE($buf, $off); $off += 2;
        
        $this->ensure($buf, $off, 2, "dexCount");
        $dexCount = $this->readUInt16LE($buf, $off); $off += 2;
        
        $dexOffsets = [];
        for ($i = 0; $i < $dexCount; $i++) {
            $this->ensure($buf, $off, 4, "dexOffsets[$i]");
            $dexOffsets[] = $this->readUInt32LE($buf, $off); $off += 4;
        }
        
        $dexCodes = [];
        
        foreach ($dexOffsets as $di => $dexOff) {
            $this->ensure($buf, $dexOff, 2, "dex[$di].methodCount");
            $p = $dexOff;
            
            $methodCount = $this->readUInt16LE($buf, $p); $p += 2;
            
            $instructions = [];
            for ($mi = 0; $mi < $methodCount; $mi++) {
                if ($p + 8 > $len) break;
                $methodIndex = $this->readUInt32LE($buf, $p); $p += 4;
                $dataSize = $this->readUInt32LE($buf, $p); $p += 4;
                
                if ($p + $dataSize > $len) {
                    break;
                }
                $data = substr($buf, $p, $dataSize);
                $p += $dataSize;
                
                $instructions[] = ['methodIndex' => $methodIndex, 'size' => $dataSize, 'data' => $data];
            }
            
            $dexCodes[] = ['methodCount' => $methodCount, 'instructions' => $instructions];
        }
        
        $entryCountHeader = isset($dexOffsets[0]) ? $methodCount : 0;
        $entryCountUsed = isset($instructions) ? count($instructions) : 0;
        $dataOffHeader = 0;
        $dataOffUsed = 0;
        $warnings = [];
        
        return [
            'version' => $version,
            'dexCount' => $dexCount,
            'dexOffsets' => $dexOffsets,
            'dexCodes' => $dexCodes,
            'magic' => 0,
            'entryCountHeader' => $entryCountHeader,
            'entryCountUsed' => $entryCountUsed,
            'dataOffHeader' => $dataOffHeader,
            'dataOffUsed' => $dataOffUsed,
            'warnings' => $warnings,
        ];
    }

    public function parseDex($dex) {
        $h = $this->readHeader($dex);
        $strings = $this->parseStrings($dex, $h);
        $types = $this->parseTypes($dex, $h, $strings);
        $methodIds = $this->coreA($dex, $h, $strings, $types);
        
        $codeOffByMethodIdx = [];
        
        for ($i = 0; $i < $h['classDefsSize']; $i++) {
            $base = $h['classDefsOff'] + $i * 32;
            $classDataOff = $this->readUInt32LE($dex, $base + 24);
            if ($classDataOff !== 0) {
                $this->parseClassDataForMethodCodeOffs($dex, $classDataOff, function($methodIdx, $codeOff) use (&$codeOffByMethodIdx) {
                    $codeOffByMethodIdx[$methodIdx] = $codeOff;
                });
            }
        }
        
        $methods = [];
        foreach ($methodIds as $m) {
            $proto = $this->parseProto($dex, $m['protoIdx'], $h, $strings, $types);
            $codeOff = isset($codeOffByMethodIdx[$m['methodIdx']]) ? $codeOffByMethodIdx[$m['methodIdx']] : null;
            $insnsOff = $codeOff ? ($codeOff + 16) : null;
            
            $methods[] = [
                'methodIdx' => $m['methodIdx'],
                'classDescriptor' => $m['classDescriptor'],
                'name' => $m['name'],
                'protoShorty' => $proto['protoShorty'],
                'returnType' => $proto['returnType'],
                'paramTypes' => $proto['paramTypes'],
                'codeOff' => $codeOff,
                'insnsOff' => $insnsOff,
            ];
        }
        
        return [
            'header' => $h,
            'strings' => $strings,
            'types' => $types,
            'methods' => $methods,
            'codeOffByMethodIdx' => $codeOffByMethodIdx,
        ];
    }

    public function patchDexInsns($dex, $insnsOff, $codeBytes) {
        if ($insnsOff < 0 || $insnsOff + strlen($codeBytes) > strlen($dex)) {
            throw new Exception("Patch would write out of bounds");
        }
        return substr_replace($dex, $codeBytes, $insnsOff, strlen($codeBytes));
    }
    public function fixDexHeaders($dex) {
        $dex = substr_replace($dex, pack('V', strlen($dex)), 0x20, 4);
        $sha1 = sha1(substr($dex, 0x20), true);
        $dex = substr_replace($dex, $sha1, 0x0c, 20);
        $sum = $this->adler32(substr($dex, 0x0c));
        $dex = substr_replace($dex, pack('V', $sum), 0x08, 4);
        
        return $dex;
    }

    public function readUleb128($buf, $offset) {
        $result = 0;
        $shift = 0;
        $len = strlen($buf);
        
        do {
            if ($offset >= $len) break;
            $cur = ord($buf[$offset++]);
            $result |= ($cur & 0x7f) << $shift;
            $shift += 7;
        } while ($cur & 0x80);
        
        return ['value' => $result & 0xFFFFFFFF, 'offset' => $offset];
    }
    
    private function classNameFromDescriptor($desc) {
        return str_replace('/', '.', preg_replace(['/^L/', '/;$/'], '', $desc));
    }
    
    private function naturalDexSort($a, $b) {
        preg_match('/^classes(\d*)\.dex$/i', $a, $ma);
        preg_match('/^classes(\d*)\.dex$/i', $b, $mb);
        
        $na = $ma ? (isset($ma[1]) && $ma[1] !== '' ? intval($ma[1]) : 1) : PHP_INT_MAX;
        $nb = $mb ? (isset($mb[1]) && $mb[1] !== '' ? intval($mb[1]) : 1) : PHP_INT_MAX;
        
        if ($na !== $nb) return $na - $nb;
        return strcmp($a, $b);
    }
    
    private function methodSig($m) {
        $params = isset($m['paramTypes']) ? implode('', $m['paramTypes']) : '';
        $return = isset($m['returnType']) ? $m['returnType'] : '';
        return $m['name'] . '(' . $params . ')' . $return;
    }
    
    private function getCodeBytes($multi, $methodIdx) {
        if (empty($multi['dexCodes'])) return null;
        foreach ($multi['dexCodes'][0]['instructions'] as $insn) {
            if ($insn['methodIndex'] == $methodIdx) {
                return $insn['data'];
            }
        }
        return null;
    }
    
    private function ensure($buf, $offset, $need, $label) {
        $len = strlen($buf);
        if ($offset < 0 || $offset + $need > $len) {
            throw new Exception("$label: need $need bytes at offset $offset, but buffer length is $len");
        }
    }
    
    private function readUInt16LE($buf, $offset) {
        $data = substr($buf, $offset, 2);
        return unpack('v', $data)[1];
    }
    
    private function readUInt32LE($buf, $offset) {
        $data = substr($buf, $offset, 4);
        return unpack('V', $data)[1];
    }
    
    private function readHeader($dex) {
        $fileSize = $this->readUInt32LE($dex, 0x20);
        
        $stringIdsSize = $this->readUInt32LE($dex, 0x38);
        $stringIdsOff  = $this->readUInt32LE($dex, 0x3c);
        $typeIdsSize   = $this->readUInt32LE($dex, 0x40);
        $typeIdsOff    = $this->readUInt32LE($dex, 0x44);
        $protoIdsSize  = $this->readUInt32LE($dex, 0x48);
        $protoIdsOff   = $this->readUInt32LE($dex, 0x4c);
        $methodIdsSize = $this->readUInt32LE($dex, 0x58);
        $methodIdsOff  = $this->readUInt32LE($dex, 0x5c);
        $classDefsSize = $this->readUInt32LE($dex, 0x60);
        $classDefsOff  = $this->readUInt32LE($dex, 0x64);
        
        return [
            'fileSize' => $fileSize,
            'stringIdsSize' => $stringIdsSize, 'stringIdsOff' => $stringIdsOff,
            'typeIdsSize' => $typeIdsSize, 'typeIdsOff' => $typeIdsOff,
            'protoIdsSize' => $protoIdsSize, 'protoIdsOff' => $protoIdsOff,
            'methodIdsSize' => $methodIdsSize, 'methodIdsOff' => $methodIdsOff,
            'classDefsSize' => $classDefsSize, 'classDefsOff' => $classDefsOff,
        ];
    }
    
    private function readString($dex, $stringDataOff) {
        $off = $stringDataOff;
        $u = $this->readUleb128($dex, $off);
        $off = $u['offset'];
        
        $end = strpos($dex, "\x00", $off);
        if ($end === false) throw new Exception("Unterminated string_data_item");
        return substr($dex, $off, $end - $off);
    }
    
    private function parseStrings($dex, $h) {
        $strings = [];
        for ($i = 0; $i < $h['stringIdsSize']; $i++) {
            $stringDataOff = $this->readUInt32LE($dex, $h['stringIdsOff'] + $i * 4);
            $strings[] = $this->readString($dex, $stringDataOff);
        }
        return $strings;
    }
    
    private function parseTypes($dex, $h, $strings) {
        $types = [];
        for ($i = 0; $i < $h['typeIdsSize']; $i++) {
            $descriptorIdx = $this->readUInt32LE($dex, $h['typeIdsOff'] + $i * 4);
            $types[] = $strings[$descriptorIdx];
        }
        return $types;
    }
    
    private function parseProto($dex, $protoIdx, $h, $strings, $types) {
        $base = $h['protoIdsOff'] + $protoIdx * 12;
        $shortyIdx = $this->readUInt32LE($dex, $base);
        $returnTypeIdx = $this->readUInt32LE($dex, $base + 4);
        $paramsOff = $this->readUInt32LE($dex, $base + 8);
        
        $protoShorty = $strings[$shortyIdx];
        $returnType = $types[$returnTypeIdx];
        
        $paramTypes = [];
        if ($paramsOff !== 0) {
            $size = $this->readUInt32LE($dex, $paramsOff);
            $p = $paramsOff + 4;
            for ($i = 0; $i < $size; $i++) {
                $typeIdx = $this->readUInt16LE($dex, $p);
                $p += 2;
                $paramTypes[] = $types[$typeIdx];
            }
        }
        
        return ['protoShorty' => $protoShorty, 'returnType' => $returnType, 'paramTypes' => $paramTypes];
    }
    
    private function coreA($dex, $h, $strings, $types) {
        $methods = [];
        for ($i = 0; $i < $h['methodIdsSize']; $i++) {
            $base = $h['methodIdsOff'] + $i * 8;
            $classIdx = $this->readUInt16LE($dex, $base);
            $protoIdx = $this->readUInt16LE($dex, $base + 2);
            $nameIdx = $this->readUInt32LE($dex, $base + 4);
            
            $classDescriptor = $types[$classIdx];
            $name = $strings[$nameIdx];
            $methods[] = ['methodIdx' => $i, 'classIdx' => $classIdx, 'protoIdx' => $protoIdx, 'name' => $name, 'classDescriptor' => $classDescriptor];
        }
        return $methods;
    }
    
    private function parseClassDataForMethodCodeOffs($dex, $classDataOff, $callback) {
        $off = $classDataOff;
        
        $a = $this->readUleb128($dex, $off); $staticFieldsSize = $a['value']; $off = $a['offset'];
        $b = $this->readUleb128($dex, $off); $instanceFieldsSize = $b['value']; $off = $b['offset'];
        $c = $this->readUleb128($dex, $off); $directMethodsSize = $c['value']; $off = $c['offset'];
        $d = $this->readUleb128($dex, $off); $virtualMethodsSize = $d['value']; $off = $d['offset'];
        
        $skipEncodedFieldList = function($n) use (&$off, $dex) {
            $fieldIdx = 0;
            for ($i = 0; $i < $n; $i++) {
                $x = $this->readUleb128($dex, $off); $fieldIdx += $x['value']; $off = $x['offset'];
                $y = $this->readUleb128($dex, $off); $off = $y['offset'];
            }
        };
        $skipEncodedFieldList($staticFieldsSize);
        $skipEncodedFieldList($instanceFieldsSize);
        
        $readEncodedMethodList = function($n) use (&$off, $dex, $callback) {
            $methodIdx = 0;
            for ($i = 0; $i < $n; $i++) {
                $m = $this->readUleb128($dex, $off); $methodIdx += $m['value']; $off = $m['offset'];
                $af = $this->readUleb128($dex, $off); $off = $af['offset'];
                $co = $this->readUleb128($dex, $off); $codeOff = $co['value']; $off = $co['offset'];
                if ($codeOff !== 0) $callback($methodIdx, $codeOff);
            }
        };
        
        $readEncodedMethodList($directMethodsSize);
        $readEncodedMethodList($virtualMethodsSize);
    }
    
    private function adler32($data) {
        $a = 1;
        $b = 0;
        $len = strlen($data);
        
        for ($i = 0; $i < $len; $i++) {
            $a = ($a + ord($data[$i])) % 65521;
            $b = ($b + $a) % 65521;
        }
        
        return ($b << 16) | $a;
    }
}

if (!class_exists('ZipArchive')) {
    throw new Exception('ZipArchive PHP zip extension no have in there');
}

?>