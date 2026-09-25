<?php
/**
 * QrGenerator
 *
 * A small, self-contained, dependency-free QR Code encoder (ISO/IEC 18004,
 * "Model 2") used to render the TOTP enrollment otpauth:// URI as a scannable
 * image directly on the WHMCS server.
 *
 * WHY THIS EXISTS / WHY IT IS WRITTEN FROM SCRATCH:
 *  - The TOTP secret must never be sent to a third-party "QR image" API —
 *    doing so would leak the shared secret to an external service.
 *  - WHMCS's own bundled "Time Based Tokens" module ships a LocalQrGenerator
 *    and RemoteQrGenerator, but its source (totp.php, ga4php.php, and every
 *    file under lib/Generator/) is ionCube-encoded, official WHMCS Ltd.
 *    protected code. Its EULA explicitly forbids reverse engineering or
 *    decompiling it, so none of that code was read, copied, or adapted here
 *    — only the *existence* of a "local generator" concept (as opposed to a
 *    remote/third-party one) informed the decision to build this file.
 *  - This implementation encodes purely against the public ISO/IEC 18004
 *    standard (Reed-Solomon error correction in GF(256), BCH format/version
 *    info, standard module placement/masking rules) — the same open
 *    algorithm used by every independent QR encoder, WHMCS's included.
 *
 * SCOPE: byte-mode encoding only (sufficient for otpauth:// URIs, which are
 * plain ASCII), versions 1-10, selectable error-correction level (defaults
 * to "M"). This covers otpauth:// URIs up to ~200 bytes, comfortably above
 * the ~90-140 byte URIs this module actually generates.
 *
 * Output is an inline SVG string — no external HTTP calls, no filesystem
 * writes, nothing leaves the process.
 */

declare(strict_types=1);

namespace WHMCS\Module\Security\DctTotpNative;

if (!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

class QrGenerator
{
    const ECC_L = 0;
    const ECC_M = 1;
    const ECC_Q = 2;
    const ECC_H = 3;

    /** Total data codewords per version/ECC (versions 1-10). */
    private static $capacityTable = [
        // version => [L, M, Q, H] total DATA codewords
        1  => [19, 16, 13, 9],
        2  => [34, 28, 22, 16],
        3  => [55, 44, 34, 26],
        4  => [80, 64, 48, 36],
        5  => [108, 86, 62, 46],
        6  => [136, 108, 76, 60],
        7  => [156, 124, 88, 66],
        8  => [194, 154, 110, 86],
        9  => [232, 182, 132, 100],
        10 => [274, 216, 154, 122],
    ];

    /** Block structure per version/ECC: [eccPerBlock, g1Count, g1Len, g2Count, g2Len] */
    private static $blockTable = [
        1  => [[7, 1, 19, 0, 0], [10, 1, 16, 0, 0], [13, 1, 13, 0, 0], [17, 1, 9, 0, 0]],
        2  => [[10, 1, 34, 0, 0], [16, 1, 28, 0, 0], [22, 1, 22, 0, 0], [28, 1, 16, 0, 0]],
        3  => [[15, 1, 55, 0, 0], [26, 1, 44, 0, 0], [18, 2, 17, 0, 0], [22, 2, 13, 0, 0]],
        4  => [[20, 1, 80, 0, 0], [18, 2, 32, 0, 0], [26, 2, 24, 0, 0], [16, 4, 9, 0, 0]],
        5  => [[26, 1, 108, 0, 0], [24, 2, 43, 0, 0], [18, 2, 15, 2, 16], [22, 2, 11, 2, 12]],
        6  => [[18, 2, 68, 0, 0], [16, 4, 27, 0, 0], [24, 4, 19, 0, 0], [28, 4, 15, 0, 0]],
        7  => [[20, 2, 78, 0, 0], [18, 4, 31, 0, 0], [18, 2, 14, 4, 15], [26, 4, 13, 1, 14]],
        8  => [[24, 2, 97, 0, 0], [22, 2, 38, 2, 39], [22, 4, 18, 2, 19], [26, 4, 14, 2, 15]],
        9  => [[30, 2, 116, 0, 0], [22, 3, 36, 2, 37], [20, 4, 16, 4, 17], [24, 4, 12, 4, 13]],
        10 => [[18, 2, 68, 2, 69], [26, 4, 43, 1, 44], [24, 6, 19, 2, 20], [28, 6, 15, 2, 16]],
    ];

    /** Alignment pattern center coordinates (excluding those that collide with finder patterns). */
    private static $alignmentTable = [
        1 => [], 2 => [6, 18], 3 => [6, 22], 4 => [6, 26], 5 => [6, 30],
        6 => [6, 34], 7 => [6, 22, 38], 8 => [6, 24, 42], 9 => [6, 26, 46], 10 => [6, 28, 50],
    ];

    /** Bits of data-remainder padding needed at the end of the bitstream per version. */
    private static $remainderBits = [
        1 => 0, 2 => 7, 3 => 7, 4 => 7, 5 => 7, 6 => 7, 7 => 0, 8 => 0, 9 => 0, 10 => 0,
    ];

    private static $formatInfoGenerator = 0x537; // x^10+x^8+x^5+x^4+x^2+x+1
    private static $formatInfoMask = 0x5412;
    private static $versionInfoGenerator = 0x1F25;

    /**
     * Build the boolean module matrix for the given data string.
     *
     * @param string $data       Payload to encode (ASCII/byte data).
     * @param int    $ecc        One of the ECC_* constants (default M).
     * @return array{matrix: bool[][], size: int, version: int}
     */
    public static function encodeMatrix($data, $ecc = self::ECC_M, $forceMask = null)
    {
        $version = self::chooseVersion(strlen($data), $ecc);
        $dataCodewords = self::buildDataCodewords($data, $version, $ecc);
        $allCodewords = self::interleaveWithEcc($dataCodewords, $version, $ecc);
        $bits = self::codewordsToBits($allCodewords);
        $bits .= str_repeat('0', self::$remainderBits[$version]);

        $size = 17 + 4 * $version;
        $matrix = array_fill(0, $size, array_fill(0, $size, false));
        $reserved = array_fill(0, $size, array_fill(0, $size, false));

        self::placeFinderPattern($matrix, $reserved, 0, 0);
        self::placeFinderPattern($matrix, $reserved, $size - 7, 0);
        self::placeFinderPattern($matrix, $reserved, 0, $size - 7);
        self::placeTimingPatterns($matrix, $reserved, $size);
        self::placeAlignmentPatterns($matrix, $reserved, $version, $size);
        self::reserveFormatAreas($reserved, $size);
        if ($version >= 7) {
            self::reserveVersionAreas($reserved, $size);
        }
        // Dark module — always present, immediately below-left of the bottom-left finder pattern.
        $matrix[4 * $version + 9][8] = true;
        $reserved[4 * $version + 9][8] = true;

        self::placeData($matrix, $reserved, $bits, $size);

        $maskId = ($forceMask !== null) ? $forceMask : self::chooseBestMask($matrix, $reserved, $size);
        self::applyMask($matrix, $reserved, $maskId, $size);
        self::placeFormatInfo($matrix, $ecc, $maskId, $size);
        if ($version >= 7) {
            self::placeVersionInfo($matrix, $version, $size);
        }

        return ['matrix' => $matrix, 'size' => $size, 'version' => $version];
    }

    /**
     * Render the given data as a self-contained inline SVG string.
     *
     * @param string $data
     * @param int    $moduleSize Pixel size of one QR module.
     * @param int    $ecc        One of the ECC_* constants.
     * @return string SVG markup (no XML prolog), safe to embed directly in HTML.
     */
    public static function generateSvg($data, $moduleSize = 6, $ecc = self::ECC_M)
    {
        try {
            $built = self::encodeMatrix($data, $ecc);
        } catch (\RuntimeException $e) {
            // Payload too large for the requested ECC level at the max supported
            // version (10) — retry at ECC L, which trades error-correction
            // strength for more usable data capacity. If it still doesn't fit,
            // let the exception propagate; callers fall back to manual-entry-only.
            if ($ecc === self::ECC_L) {
                throw $e;
            }
            $built = self::encodeMatrix($data, self::ECC_L);
        }
        $matrix = $built['matrix'];
        $size = $built['size'];
        $quiet = 4; // quiet zone modules, per spec minimum
        $dim = ($size + 2 * $quiet) * $moduleSize;

        $rects = '';
        for ($r = 0; $r < $size; $r++) {
            for ($c = 0; $c < $size; $c++) {
                if ($matrix[$r][$c]) {
                    $x = ($c + $quiet) * $moduleSize;
                    $y = ($r + $quiet) * $moduleSize;
                    $rects .= '<rect x="' . $x . '" y="' . $y . '" width="' . $moduleSize . '" height="' . $moduleSize . '"/>';
                }
            }
        }

        return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' . $dim . ' ' . $dim . '" '
            . 'width="' . $dim . '" height="' . $dim . '" shape-rendering="crispEdges">'
            . '<rect x="0" y="0" width="' . $dim . '" height="' . $dim . '" fill="#ffffff"/>'
            . '<g fill="#000000">' . $rects . '</g>'
            . '</svg>';
    }

    // ------------------------------------------------------------------
    // Data codeword construction
    // ------------------------------------------------------------------

    private static function chooseVersion($byteLength, $ecc)
    {
        foreach (self::$capacityTable as $version => $capacities) {
            $totalDataCodewords = $capacities[$ecc];
            $countBits = ($version <= 9) ? 8 : 16;
            $headerBits = 4 + $countBits;
            $capacityBits = $totalDataCodewords * 8;
            if ($headerBits + $byteLength * 8 + 4 <= $capacityBits) {
                return $version;
            }
        }
        throw new \RuntimeException('Data too large to encode as a QR code (max supported: version 10).');
    }

    private static function buildDataCodewords($data, $version, $ecc)
    {
        $len = strlen($data);
        $countBits = ($version <= 9) ? 8 : 16;

        $bits = '0100'; // byte mode indicator
        $bits .= str_pad(decbin($len), $countBits, '0', STR_PAD_LEFT);
        for ($i = 0; $i < $len; $i++) {
            $bits .= str_pad(decbin(ord($data[$i])), 8, '0', STR_PAD_LEFT);
        }

        $totalDataCodewords = self::$capacityTable[$version][$ecc];
        $capacityBits = $totalDataCodewords * 8;

        // Terminator (up to 4 zero bits).
        $bits .= str_repeat('0', min(4, $capacityBits - strlen($bits)));
        // Pad to a byte boundary.
        if (strlen($bits) % 8 !== 0) {
            $bits .= str_repeat('0', 8 - (strlen($bits) % 8));
        }

        $codewords = [];
        for ($i = 0; $i < strlen($bits); $i += 8) {
            $codewords[] = bindec(substr($bits, $i, 8));
        }

        $padBytes = [0xEC, 0x11];
        $i = 0;
        while (count($codewords) < $totalDataCodewords) {
            $codewords[] = $padBytes[$i % 2];
            $i++;
        }

        return $codewords;
    }

    // ------------------------------------------------------------------
    // Reed-Solomon error correction (GF(256), primitive polynomial 0x11D)
    // ------------------------------------------------------------------

    private static $gfExp = null;
    private static $gfLog = null;

    private static function initGaloisField()
    {
        if (self::$gfExp !== null) {
            return;
        }
        $exp = array_fill(0, 512, 0);
        $log = array_fill(0, 256, 0);
        $x = 1;
        for ($i = 0; $i < 255; $i++) {
            $exp[$i] = $x;
            $log[$x] = $i;
            $x <<= 1;
            if ($x & 0x100) {
                $x ^= 0x11D;
            }
        }
        for ($i = 255; $i < 512; $i++) {
            $exp[$i] = $exp[$i - 255];
        }
        self::$gfExp = $exp;
        self::$gfLog = $log;
    }

    private static function gfMul($a, $b)
    {
        if ($a === 0 || $b === 0) {
            return 0;
        }
        return self::$gfExp[self::$gfLog[$a] + self::$gfLog[$b]];
    }

    private static function generatorPolynomial($degree)
    {
        $poly = [1];
        for ($i = 0; $i < $degree; $i++) {
            $next = array_fill(0, count($poly) + 1, 0);
            for ($j = 0; $j < count($poly); $j++) {
                $next[$j] ^= $poly[$j];
                $next[$j + 1] ^= self::gfMul($poly[$j], self::$gfExp[$i]);
            }
            $poly = $next;
        }
        return $poly;
    }

    private static function rsEncode(array $dataCodewords, $eccLen)
    {
        self::initGaloisField();
        $generator = self::generatorPolynomial($eccLen);
        $remainder = array_fill(0, $eccLen, 0);

        foreach ($dataCodewords as $codeword) {
            $factor = $codeword ^ $remainder[0];
            array_shift($remainder);
            $remainder[] = 0;
            if ($factor !== 0) {
                for ($i = 0; $i < $eccLen; $i++) {
                    $remainder[$i] ^= self::gfMul($generator[$i + 1], $factor);
                }
            }
        }

        return $remainder;
    }

    private static function interleaveWithEcc(array $dataCodewords, $version, $ecc)
    {
        list($eccLen, $g1Count, $g1Len, $g2Count, $g2Len) = self::$blockTable[$version][$ecc];

        $blocks = [];
        $eccBlocks = [];
        $offset = 0;
        for ($b = 0; $b < $g1Count; $b++) {
            $block = array_slice($dataCodewords, $offset, $g1Len);
            $blocks[] = $block;
            $eccBlocks[] = self::rsEncode($block, $eccLen);
            $offset += $g1Len;
        }
        for ($b = 0; $b < $g2Count; $b++) {
            $block = array_slice($dataCodewords, $offset, $g2Len);
            $blocks[] = $block;
            $eccBlocks[] = self::rsEncode($block, $eccLen);
            $offset += $g2Len;
        }

        $maxDataLen = max($g1Len, $g2Len > 0 ? $g2Len : 0);
        $result = [];
        for ($i = 0; $i < $maxDataLen; $i++) {
            foreach ($blocks as $block) {
                if (isset($block[$i])) {
                    $result[] = $block[$i];
                }
            }
        }
        for ($i = 0; $i < $eccLen; $i++) {
            foreach ($eccBlocks as $eccBlock) {
                $result[] = $eccBlock[$i];
            }
        }

        return $result;
    }

    private static function codewordsToBits(array $codewords)
    {
        $bits = '';
        foreach ($codewords as $cw) {
            $bits .= str_pad(decbin($cw), 8, '0', STR_PAD_LEFT);
        }
        return $bits;
    }

    // ------------------------------------------------------------------
    // Module placement
    // ------------------------------------------------------------------

    private static function placeFinderPattern(&$matrix, &$reserved, $topRow, $topCol)
    {
        for ($r = -1; $r <= 7; $r++) {
            for ($c = -1; $c <= 7; $c++) {
                $rr = $topRow + $r;
                $cc = $topCol + $c;
                if ($rr < 0 || $cc < 0 || $rr >= count($matrix) || $cc >= count($matrix)) {
                    continue;
                }
                $reserved[$rr][$cc] = true;
                if ($r < 0 || $r > 6 || $c < 0 || $c > 6) {
                    $matrix[$rr][$cc] = false; // separator (white)
                    continue;
                }
                $isBorder = ($r === 0 || $r === 6 || $c === 0 || $c === 6);
                $isCore = ($r >= 2 && $r <= 4 && $c >= 2 && $c <= 4);
                $matrix[$rr][$cc] = $isBorder || $isCore;
            }
        }
    }

    private static function placeTimingPatterns(&$matrix, &$reserved, $size)
    {
        for ($i = 8; $i < $size - 8; $i++) {
            $on = ($i % 2 === 0);
            $matrix[6][$i] = $on;
            $reserved[6][$i] = true;
            $matrix[$i][6] = $on;
            $reserved[$i][6] = true;
        }
    }

    private static function placeAlignmentPatterns(&$matrix, &$reserved, $version, $size)
    {
        $coords = self::$alignmentTable[$version];
        if (empty($coords)) {
            return;
        }
        foreach ($coords as $row) {
            foreach ($coords as $col) {
                // Skip positions overlapping the three finder patterns.
                if (($row <= 8 && $col <= 8) || ($row <= 8 && $col >= $size - 9) || ($row >= $size - 9 && $col <= 8)) {
                    continue;
                }
                for ($r = -2; $r <= 2; $r++) {
                    for ($c = -2; $c <= 2; $c++) {
                        $rr = $row + $r;
                        $cc = $col + $c;
                        $reserved[$rr][$cc] = true;
                        $dist = max(abs($r), abs($c));
                        $matrix[$rr][$cc] = ($dist !== 1);
                    }
                }
            }
        }
    }

    private static function reserveFormatAreas(&$reserved, $size)
    {
        for ($i = 0; $i <= 8; $i++) {
            $reserved[8][$i] = true;
            $reserved[$i][8] = true;
        }
        for ($i = 0; $i < 8; $i++) {
            $reserved[8][$size - 1 - $i] = true;
            $reserved[$size - 1 - $i][8] = true;
        }
    }

    private static function reserveVersionAreas(&$reserved, $size)
    {
        for ($r = 0; $r < 6; $r++) {
            for ($c = 0; $c < 3; $c++) {
                $reserved[$r][$size - 11 + $c] = true;
                $reserved[$size - 11 + $c][$r] = true;
            }
        }
    }

    private static function placeData(&$matrix, &$reserved, $bits, $size)
    {
        $bitIndex = 0;
        $bitLen = strlen($bits);
        $upward = true;
        $col = $size - 1;

        while ($col > 0) {
            if ($col === 6) {
                $col--; // skip vertical timing pattern column
            }
            $rows = $upward ? range($size - 1, 0) : range(0, $size - 1);
            foreach ($rows as $row) {
                for ($cOffset = 0; $cOffset < 2; $cOffset++) {
                    $cc = $col - $cOffset;
                    if ($reserved[$row][$cc]) {
                        continue;
                    }
                    $bit = ($bitIndex < $bitLen) ? ($bits[$bitIndex] === '1') : false;
                    $matrix[$row][$cc] = $bit;
                    $bitIndex++;
                }
            }
            $upward = !$upward;
            $col -= 2;
        }
    }

    // ------------------------------------------------------------------
    // Masking
    // ------------------------------------------------------------------

    private static function maskCondition($maskId, $r, $c)
    {
        switch ($maskId) {
            case 0: return (($r + $c) % 2) === 0;
            case 1: return ($r % 2) === 0;
            case 2: return ($c % 3) === 0;
            case 3: return (($r + $c) % 3) === 0;
            case 4: return ((intdiv($r, 2) + intdiv($c, 3)) % 2) === 0;
            case 5: return ((($r * $c) % 2) + (($r * $c) % 3)) === 0;
            case 6: return ((($r * $c) % 2) + (($r * $c) % 3)) % 2 === 0;
            case 7: return ((($r + $c) % 2) + (($r * $c) % 3)) % 2 === 0;
        }
        return false;
    }

    private static function applyMask(&$matrix, &$reserved, $maskId, $size)
    {
        for ($r = 0; $r < $size; $r++) {
            for ($c = 0; $c < $size; $c++) {
                if ($reserved[$r][$c]) {
                    continue;
                }
                if (self::maskCondition($maskId, $r, $c)) {
                    $matrix[$r][$c] = !$matrix[$r][$c];
                }
            }
        }
    }

    private static function chooseBestMask(&$matrix, &$reserved, $size)
    {
        $best = 0;
        $bestPenalty = null;
        for ($maskId = 0; $maskId < 8; $maskId++) {
            $trial = $matrix;
            self::applyMask($trial, $reserved, $maskId, $size);
            $penalty = self::maskPenalty($trial, $size);
            if ($bestPenalty === null || $penalty < $bestPenalty) {
                $bestPenalty = $penalty;
                $best = $maskId;
            }
        }
        return $best;
    }

    private static function maskPenalty(array $matrix, $size)
    {
        $penalty = 0;

        // Rule 1: runs of 5+ same-color modules, per row and column.
        foreach ([true, false] as $byRow) {
            for ($i = 0; $i < $size; $i++) {
                $runLen = 1;
                $prev = null;
                for ($j = 0; $j < $size; $j++) {
                    $val = $byRow ? $matrix[$i][$j] : $matrix[$j][$i];
                    if ($val === $prev) {
                        $runLen++;
                    } else {
                        if ($runLen >= 5) {
                            $penalty += 3 + ($runLen - 5);
                        }
                        $runLen = 1;
                        $prev = $val;
                    }
                }
                if ($runLen >= 5) {
                    $penalty += 3 + ($runLen - 5);
                }
            }
        }

        // Rule 2: 2x2 blocks of same color.
        for ($r = 0; $r < $size - 1; $r++) {
            for ($c = 0; $c < $size - 1; $c++) {
                $v = $matrix[$r][$c];
                if ($v === $matrix[$r][$c + 1] && $v === $matrix[$r + 1][$c] && $v === $matrix[$r + 1][$c + 1]) {
                    $penalty += 3;
                }
            }
        }

        // Rule 3: finder-like patterns 1:1:3:1:1 with 4-module light padding.
        $pattern = [true, false, true, true, true, false, true, false, false, false, false];
        $patternRev = array_reverse($pattern);
        for ($r = 0; $r < $size; $r++) {
            for ($c = 0; $c <= $size - 11; $c++) {
                $slice = array_slice($matrix[$r], $c, 11);
                if ($slice === $pattern || $slice === $patternRev) {
                    $penalty += 40;
                }
            }
        }
        for ($c = 0; $c < $size; $c++) {
            for ($r = 0; $r <= $size - 11; $r++) {
                $slice = [];
                for ($k = 0; $k < 11; $k++) {
                    $slice[] = $matrix[$r + $k][$c];
                }
                if ($slice === $pattern || $slice === $patternRev) {
                    $penalty += 40;
                }
            }
        }

        // Rule 4: overall dark/light balance.
        $dark = 0;
        foreach ($matrix as $row) {
            foreach ($row as $v) {
                if ($v) {
                    $dark++;
                }
            }
        }
        $total = $size * $size;
        $percent = ($dark * 100) / $total;
        $penalty += (int) (abs((int) floor($percent / 5) * 5 - 50) / 5) * 10;

        return $penalty;
    }

    // ------------------------------------------------------------------
    // Format / version info (BCH encoded)
    // ------------------------------------------------------------------

    private static function bchEncode($data, $generator, $genBits)
    {
        $g = $generator;
        $d = $data << ($genBits - 1);
        $msbPos = self::msbPosition($d);
        $genMsbPos = self::msbPosition($g);
        while ($msbPos >= $genMsbPos) {
            $d ^= ($g << ($msbPos - $genMsbPos));
            $msbPos = self::msbPosition($d);
            if ($d === 0) {
                break;
            }
        }
        return ($data << ($genBits - 1)) | $d;
    }

    private static function msbPosition($v)
    {
        if ($v === 0) {
            return -1;
        }
        $pos = 0;
        while ($v > 1) {
            $v >>= 1;
            $pos++;
        }
        return $pos;
    }

    private static function placeFormatInfo(&$matrix, $ecc, $maskId, $size)
    {
        // Format info ECC-level bit ordering: L=01, M=00, Q=11, H=10.
        $eccBits = [self::ECC_L => 0b01, self::ECC_M => 0b00, self::ECC_Q => 0b11, self::ECC_H => 0b10];
        $data = ($eccBits[$ecc] << 3) | $maskId;
        $encoded = self::bchEncode($data, self::$formatInfoGenerator, 11);
        $bits = $encoded ^ self::$formatInfoMask;
        $bitStr = str_pad(decbin($bits), 15, '0', STR_PAD_LEFT);

        // Around top-left finder pattern.
        $col6 = [0, 1, 2, 3, 4, 5, 7, 8];
        for ($i = 0; $i < 8; $i++) {
            $matrix[8][$col6[$i]] = $bitStr[$i] === '1';
        }
        $row6 = [8, 7, 5, 4, 3, 2, 1, 0];
        for ($i = 0; $i < 8; $i++) {
            $matrix[$row6[$i]][8] = $bitStr[14 - $i] === '1';
        }

        // Bottom-left / top-right copies.
        for ($i = 0; $i < 7; $i++) {
            $matrix[$size - 1 - $i][8] = $bitStr[$i] === '1';
        }
        for ($i = 0; $i < 8; $i++) {
            $matrix[8][$size - 8 + $i] = $bitStr[7 + $i] === '1';
        }
    }

    private static function placeVersionInfo(&$matrix, $version, $size)
    {
        $encoded = self::bchEncode($version, self::$versionInfoGenerator, 13);
        $bitStr = str_pad(decbin($encoded), 18, '0', STR_PAD_LEFT);
        // bitStr[0] is the MSB, corresponding to (version<<12) bit; place LSB-first into the grid.
        for ($i = 0; $i < 18; $i++) {
            $bit = $bitStr[17 - $i] === '1';
            $row = intdiv($i, 3);
            $col = $i % 3;
            $matrix[$row][$size - 11 + $col] = $bit;
            $matrix[$size - 11 + $col][$row] = $bit;
        }
    }
}
