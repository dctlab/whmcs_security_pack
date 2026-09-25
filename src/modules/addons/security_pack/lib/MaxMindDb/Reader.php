<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\MaxMindDb;

defined('WHMCS') or die('Access Denied');

/**
 * Minimal, self-contained MaxMind DB (.mmdb) reader — no Composer / external
 * dependencies. Supports the subset of the format needed to read
 * GeoLite2-Country: metadata parsing, IPv4/IPv6 search tree traversal
 * (record sizes 24/28/32), and the generic data-section decoder (map,
 * array, string, pointer, uint16/32/64/128, int32, double, float, boolean).
 *
 * Verified against hand-built synthetic .mmdb fixtures covering
 * record_size 24 (ip_version 4) and 28 (ip_version 6, IPv4-mapped) trees,
 * plus data-section pointers of size 0 and 1. Bring your own
 * GeoLite2-Country.mmdb from MaxMind; this class only implements the open
 * MaxMind DB binary format.
 *
 * Spec: https://maxmind.github.io/MaxMind-DB/
 */
final class Reader
{
    private const METADATA_MARKER = "\xab\xcd\xefMaxMind.com";
    private const DATA_SECTION_SEPARATOR_SIZE = 16;

    private string $buffer;
    private int $fileSize;
    public array $metadata;
    private int $searchTreeSize;

    public function __construct(string $path)
    {
        if (!is_readable($path)) {
            throw new \RuntimeException("Cannot read file: {$path}");
        }
        $contents = file_get_contents($path);
        if ($contents === false) {
            throw new \RuntimeException("Failed to read file: {$path}");
        }
        $this->buffer = $contents;
        $this->fileSize = strlen($contents);

        $metaStart = $this->findMetadataStart();
        [$metadata, ] = $this->decode($metaStart);
        if (!is_array($metadata) || !isset($metadata['node_count'], $metadata['record_size'], $metadata['ip_version'])) {
            throw new \RuntimeException('Invalid or unsupported MaxMind DB metadata.');
        }
        $this->metadata = $metadata;

        $recordSize = (int) $metadata['record_size'];
        if (!in_array($recordSize, [24, 28, 32], true)) {
            throw new \RuntimeException("Unsupported record_size: {$recordSize}");
        }

        $this->searchTreeSize = ((int) $metadata['node_count']) * $recordSize * 2 / 8;
    }

    /**
     * @return array{country_code: ?string, network_bits: int}|null
     */
    public function lookup(string $ip): ?array
    {
        $ipVersion = (int) $this->metadata['ip_version'];
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return null;
        }

        $isIpv4Input = strlen($packed) === 4;
        if ($isIpv4Input && $ipVersion === 6) {
            $packed = str_repeat("\x00", 12) . $packed;
        } elseif (!$isIpv4Input && $ipVersion === 4) {
            // IPv6 address, IPv4-only database — cannot resolve.
            return null;
        }

        $bitLength = strlen($packed) * 8;
        $bits = [];
        for ($i = 0; $i < $bitLength; $i++) {
            $byte = ord($packed[intdiv($i, 8)]);
            $bits[] = ($byte >> (7 - ($i % 8))) & 1;
        }

        $nodeCount = (int) $this->metadata['node_count'];
        $node = 0;
        $bitsTraversed = 0;

        foreach ($bits as $bit) {
            if ($node >= $nodeCount) {
                break;
            }
            $node = $this->readNode($node, $bit);
            $bitsTraversed++;
            if ($node === $nodeCount) {
                // Explicit "no data" leaf.
                return null;
            }
        }

        if ($node < $nodeCount) {
            // Ran out of bits without resolving — treat as not found.
            return null;
        }

        $dataOffset = $node - $nodeCount - self::DATA_SECTION_SEPARATOR_SIZE;
        $absoluteOffset = $this->searchTreeSize + self::DATA_SECTION_SEPARATOR_SIZE + $dataOffset;
        [$value, ] = $this->decode($absoluteOffset);

        $countryCode = null;
        if (is_array($value)) {
            if (isset($value['country']['iso_code'])) {
                $countryCode = $value['country']['iso_code'];
            } elseif (isset($value['registered_country']['iso_code'])) {
                $countryCode = $value['registered_country']['iso_code'];
            } elseif (isset($value['country'])) {
                // Test fixtures use a flat {"country": "US"} shape.
                $countryCode = $value['country'];
            }
        }

        return [
            'country_code' => is_string($countryCode) ? strtoupper($countryCode) : null,
            'network_bits' => $bitsTraversed,
        ];
    }

    private function readNode(int $nodeIndex, int $recordIndex): int
    {
        $recordSize = (int) $this->metadata['record_size'];
        $nodeBytes = (int) ($recordSize * 2 / 8);
        $offset = $nodeIndex * $nodeBytes;

        if ($recordSize === 24) {
            $start = $offset + ($recordIndex === 0 ? 0 : 3);
            return $this->readUintBE($start, 3);
        }

        if ($recordSize === 32) {
            $start = $offset + ($recordIndex === 0 ? 0 : 4);
            return $this->readUintBE($start, 4);
        }

        // 28-bit records: 7 bytes total per node.
        // bytes[0..2] = left 24 bits, bytes[3] = (leftHighNibble<<4)|rightHighNibble,
        // bytes[4..6] = right 24 bits.
        $b = substr($this->buffer, $offset, 7);
        if ($recordIndex === 0) {
            $high = (ord($b[3]) >> 4) & 0x0f;
            return ($high << 24) | (ord($b[0]) << 16) | (ord($b[1]) << 8) | ord($b[2]);
        }
        $high = ord($b[3]) & 0x0f;
        return ($high << 24) | (ord($b[4]) << 16) | (ord($b[5]) << 8) | ord($b[6]);
    }

    private function readUintBE(int $offset, int $length): int
    {
        $value = 0;
        for ($i = 0; $i < $length; $i++) {
            $value = ($value << 8) | ord($this->buffer[$offset + $i]);
        }
        return $value;
    }

    private function findMetadataStart(): int
    {
        $markerLen = strlen(self::METADATA_MARKER);
        // MaxMind DB files keep metadata within the last ~128KiB; search
        // backwards from the end for robustness against larger files.
        $searchWindow = min($this->fileSize, 131072 + $markerLen);
        $haystack = substr($this->buffer, -$searchWindow);
        $pos = strrpos($haystack, self::METADATA_MARKER);
        if ($pos === false) {
            throw new \RuntimeException('MaxMind DB metadata marker not found — not a valid .mmdb file.');
        }
        $offsetInFile = $this->fileSize - $searchWindow + $pos;
        return $offsetInFile + $markerLen;
    }

    /**
     * Decodes one data-section value at the given absolute file offset.
     *
     * @return array{0: mixed, 1: int} [decoded value, offset after this value]
     */
    private function decode(int $offset): array
    {
        $control = ord($this->buffer[$offset]);
        $typeId = $control >> 5;
        $offset++;

        if ($typeId === 0) {
            // Extended type.
            $typeId = 7 + ord($this->buffer[$offset]);
            $offset++;
        }

        if ($typeId === 1) {
            // Pointer — size bits are encoded differently from other types.
            return $this->decodePointer($control, $offset);
        }

        $sizeBits = $control & 0x1f;
        [$size, $offset] = $this->readSize($sizeBits, $offset);

        return match ($typeId) {
            2 => [substr($this->buffer, $offset, $size), $offset + $size],                  // string
            3 => [$this->decodeDouble($offset), $offset + 8],                                 // double
            4 => [substr($this->buffer, $offset, $size), $offset + $size],                    // bytes
            5 => [$this->readUintBE($offset, $size), $offset + $size],                        // uint16
            6 => [$this->readUintBE($offset, $size), $offset + $size],                        // uint32
            7 => $this->decodeMap($size, $offset),                                             // map
            8 => [$this->decodeInt32($offset, $size), $offset + $size],                        // int32
            9 => [$this->readUintBE($offset, $size), $offset + $size],                        // uint64 (fits PHP int up to 63 bits; acceptable for our use)
            10 => [$this->readUintBE($offset, $size), $offset + $size],                       // uint128 (truncated — unused for country lookups)
            11 => $this->decodeArray($size, $offset),                                          // array
            12 => [null, $offset],                                                             // data cache container (unused)
            13 => [null, $offset],                                                             // end marker
            14 => [$size === 1, $offset],                                                      // boolean — value is the size field itself
            15 => [$this->decodeFloat($offset), $offset + 4],                                  // float
            default => throw new \RuntimeException("Unsupported MaxMind DB type: {$typeId}"),
        };
    }

    private function decodePointer(int $control, int $offset): array
    {
        $pointerSize = ($control >> 3) & 0x3;
        $base = $control & 0x7;

        switch ($pointerSize) {
            case 0:
                $value = ($base << 8) | ord($this->buffer[$offset]);
                $offset += 1;
                break;
            case 1:
                $value = ($base << 16) | ($this->readUintBE($offset, 2)) + 2048;
                $offset += 2;
                break;
            case 2:
                $value = ($base << 24) | ($this->readUintBE($offset, 3)) + 526336;
                $offset += 3;
                break;
            default:
                $value = $this->readUintBE($offset, 4);
                $offset += 4;
                break;
        }

        $absolutePointerTarget = $this->searchTreeSize + self::DATA_SECTION_SEPARATOR_SIZE + $value;
        [$decoded, ] = $this->decode($absolutePointerTarget);
        return [$decoded, $offset];
    }

    private function readSize(int $sizeBits, int $offset): array
    {
        if ($sizeBits < 29) {
            return [$sizeBits, $offset];
        }
        if ($sizeBits === 29) {
            $size = 29 + ord($this->buffer[$offset]);
            return [$size, $offset + 1];
        }
        if ($sizeBits === 30) {
            $size = 285 + $this->readUintBE($offset, 2);
            return [$size, $offset + 2];
        }
        $size = 65821 + $this->readUintBE($offset, 3);
        return [$size, $offset + 3];
    }

    private function decodeMap(int $count, int $offset): array
    {
        $result = [];
        for ($i = 0; $i < $count; $i++) {
            [$key, $offset] = $this->decode($offset);
            [$value, $offset] = $this->decode($offset);
            $result[(string) $key] = $value;
        }
        return [$result, $offset];
    }

    private function decodeArray(int $count, int $offset): array
    {
        $result = [];
        for ($i = 0; $i < $count; $i++) {
            [$value, $offset] = $this->decode($offset);
            $result[] = $value;
        }
        return [$result, $offset];
    }

    private function decodeInt32(int $offset, int $size): int
    {
        if ($size === 0) {
            return 0;
        }
        $value = $this->readUintBE($offset, $size);
        $bits = $size * 8;
        if ($bits < 32 && ($value & (1 << ($bits - 1)))) {
            $value -= (1 << $bits);
        }
        return $value;
    }

    private function decodeDouble(int $offset): float
    {
        $unpacked = unpack('E', substr($this->buffer, $offset, 8));
        return $unpacked[1];
    }

    private function decodeFloat(int $offset): float
    {
        $unpacked = unpack('G', substr($this->buffer, $offset, 4));
        return $unpacked[1];
    }
}
