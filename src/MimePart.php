<?php

/** @noinspection PhpUnused */

namespace AS2;

class MimePart
{

    const EOL = "\r\n";

    const TYPE_PKCS7_MIME        = 'application/pkcs7-mime';
    const TYPE_X_PKCS7_MIME      = 'application/x-pkcs7-mime';
    const TYPE_PKCS7_SIGNATURE   = 'application/pkcs7-signature';
    const TYPE_X_PKCS7_SIGNATURE = 'application/x-pkcs7-signature';

    const MULTIPART_SIGNED = 'multipart/signed';
    const MULTIPART_REPORT = 'multipart/report';

    const SMIME_TYPE_COMPRESSED = 'compressed-data';
    const SMIME_TYPE_ENCRYPTED  = 'enveloped-data';
    const SMIME_TYPE_SIGNED     = 'signed-data';

    const ENCODING_7BIT            = '7bit';
    const ENCODING_8BIT            = '8bit';
    const ENCODING_QUOTEDPRINTABLE = 'quoted-printable';
    const ENCODING_BASE64          = 'base64';

    /**
     * @var string
     */
    protected $rawMessage;

    /**
     * @var string
     */
    protected $body;

    /**
     * @var array
     */
    protected $parts = [];

    /** @var array<string, string> Map of lowercase header name => original name at registration */
    private $headerNames  = [];

    /** @var array<string, string[]> Map of all registered headers, as original name => array of values */
    private $headers = [];

    /**
     * MimePart constructor.
     *
     * @param array  $headers
     * @param string $body
     * @param string $rawMessage
     */
    public function __construct($headers = [], $body = null, $rawMessage = null)
    {
        if (null !== $rawMessage) {
            $this->rawMessage = $rawMessage;
        }

        $this->setHeaders($this->normalizeHeaders($headers));

        if (!is_null($body)) {
            $this->setBody($body);
        }
    }

    /**
     * Instantiate from Request Object.
     *
     * @return static
     */
    public static function fromPsrMessage($message)
    {
        return new static($message->getHeaders(), $message->getBody()->getContents());
    }

    /**
     * Instantiate from Request Object.
     *
     * @return static
     *
     * @deprecated Please use MimePart::fromPsrMessage
     */
    public static function fromRequest($request)
    {
        return self::fromPsrMessage($request);
    }

    /**
     * Instantiate from raw message string.
     *
     * @param string $rawMessage
     * @param bool   $saveRaw
     *
     * @return static
     */
    public static function fromString($rawMessage, $saveRaw = true)
    {
        $payload = Utils::parseMessage($rawMessage);

        return new static($payload['headers'], $payload['body'], $saveRaw ? $rawMessage : null);
    }

    /**
     * @return bool
     */
    public function isPkc7Mime()
    {
        $type = $this->getParsedHeader('content-type', 0, 0);
        $type = strtolower($type);

        return $type === self::TYPE_PKCS7_MIME || $type === self::TYPE_X_PKCS7_MIME;
    }

    /**
     * @return bool
     */
    public function isPkc7Signature()
    {
        $type = $this->getParsedHeader('content-type', 0, 0);
        $type = strtolower($type);

        return $type === self::TYPE_PKCS7_SIGNATURE || $type === self::TYPE_X_PKCS7_SIGNATURE;
    }

    /**
     * @return bool
     */
    public function isEncrypted()
    {
        return $this->getParsedHeader('content-type', 0, 'smime-type') === self::SMIME_TYPE_ENCRYPTED;
    }

    /**
     * @return bool
     */
    public function isCompressed()
    {
        return $this->getParsedHeader('content-type', 0, 'smime-type') === self::SMIME_TYPE_COMPRESSED;
    }

    /**
     * @return bool
     */
    public function isSigned()
    {
        return $this->getParsedHeader('content-type', 0, 0) === self::MULTIPART_SIGNED;
    }

    /**
     * @return bool
     */
    public function isReport()
    {
        $isReport = $this->getParsedHeader('content-type', 0, 0) === self::MULTIPART_REPORT;

        if ($isReport) {
            return true;
        }

        if ($this->isSigned()) {
            foreach ($this->getParts() as $part) {
                if ($part->isReport()) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @return bool
     */
    public function isBinary()
    {
        return $this->getParsedHeader('content-transfer-encoding', 0, 0) === 'binary';
    }

    /**
     * @return bool
     */
    public function getCountParts()
    {
        return count($this->parts);
    }

    /**
     * @return bool
     */
    public function isMultiPart()
    {
        return count($this->parts) > 1;
    }

    /**
     * @return MimePart[]
     */
    public function getParts()
    {
        return $this->parts;
    }

    /**
     * @param $num
     *
     * @return static|null
     */
    public function getPart($num)
    {
        return isset($this->parts[$num]) ? $this->parts[$num] : null;
    }

    /**
     * @param mixed $part
     *
     * @return $this
     */
    public function addPart($part)
    {
        if ($part instanceof static) {
            $this->parts[] = $part;
        } else {
            $this->parts[] = self::fromString((string) $part);
        }

        return $this;
    }

    /**
     * @param int $num
     *
     * @return bool
     */
    public function removePart($num)
    {
        if (isset($this->parts[$num])) {
            unset($this->parts[$num]);

            return true;
        }

        return false;
    }

    /**
     * @return string
     */
    public function getHeaderLines()
    {
        return Utils::normalizeHeaders($this->headers, self::EOL);
    }

    /**
     * @param string     $header
     * @param int        $index
     * @param string|int $param
     *
     * @return array|string|null
     */
    public function getParsedHeader($header, $index = null, $param = null)
    {
        /** @noinspection CallableParameterUseCaseInTypeContextInspection */
        $header = Utils::parseHeader($this->getHeader($header));
        if ($index === null) {
            return $header;
        }
        $params = isset($header[$index]) ? $header[$index] : [];
        if ($param !== null) {
            return isset($params[$param]) ? $params[$param] : null;
        }

        return $params;
    }

    /**
     * Return the currently set message body.
     *
     * @return string
     */
    public function getBody()
    {
        $body = $this->body;
        if (count($this->parts) > 0) {
            $boundary = $this->getParsedHeader('content-type', 0, 'boundary');
            if ($boundary) {
                //                $body .= self::EOL;
                foreach ($this->getParts() as $part) {
                    //                    $body .= self::EOL;
                    $body .= '--' . $boundary . self::EOL;
                    $body .= $part->toString() . self::EOL;
                }
                $body .= '--' . $boundary . '--' . self::EOL;
            }
        }

        return $body;
    }

    /**
     * @param static|array|string $body
     *
     * @return $this
     */
    public function setBody($body)
    {
        if ($body instanceof static) {
            $this->addPart($body);
        } elseif (is_array($body)) {
            foreach ($body as $part) {
                $this->addPart($part);
            }
        } else {
            $boundary = $this->getParsedHeader('content-type', 0, 'boundary');

            if ($boundary) {
                $parts = explode('--' . $boundary, $body);
                array_shift($parts); // remove unecessary first element
                array_pop($parts); // remove unecessary last element

                foreach ($parts as $part) {
                    $part = preg_replace('/^\r?\n|\r?\n$/','',$part,2);	//!!! MS added ,2 else we get problems when the message genuinely has new line on end

                    $this->addPart($part);
                }
            } else {
                $this->body = $body;
            }
        }

        return $this;
    }

    /**
     * @return $this|self
     */
    public function withoutRaw()
    {
        $this->rawMessage = null;

        return $this;
    }

    /**
     * Serialize to string.
     *
     * @return string
     */
    public function toString()
    {
        if ($this->rawMessage) {
            return $this->rawMessage;
        }

        return $this->getHeaderLines() . self::EOL . $this->getBody();
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->toString();
    }

    /**
     * @param $headers
     *
     * @return array
     */
    private function normalizeHeaders($headers)
    {
        if (is_array($headers)) {
            foreach ($headers as $key => $value) {
                if (strtolower($key) === 'content-type') {
                    $headers[$key] = str_replace('x-pkcs7-', 'pkcs7-', $headers[$key]);
                }
            }
        }

        return $headers;
    }






    /**
     * below all taken from GuzzleHttp\Psr7\MessageTrait, trait itself has return types causing issues
     */
    public function withHeader($header, $value)
    {
        $this->assertHeader($header);
        $value = $this->normalizeHeaderValue($value);
        $normalized = strtolower($header);

        $new = clone $this;
        if (isset($new->headerNames[$normalized])) {
            unset($new->headers[$new->headerNames[$normalized]]);
        }
        $new->headerNames[$normalized] = $header;
        $new->headers[$header] = $value;

        return $new;
    }

    /**
     * @param mixed $value
     *
     * @return string[]
     */
    private function normalizeHeaderValue($value): array
    {
        if (!is_array($value)) {
            return $this->trimAndValidateHeaderValues([$value]);
        }

        if (count($value) === 0) {
            throw new \InvalidArgumentException('Header value can not be an empty array.');
        }

        return $this->trimAndValidateHeaderValues($value);
    }

    /**
     * @see https://tools.ietf.org/html/rfc7230#section-3.2
     *
     * @param mixed $header
     */
    private function assertHeader($header): void
    {
        if (!is_string($header)) {
            throw new \InvalidArgumentException(sprintf(
                'Header name must be a string but %s provided.',
                is_object($header) ? get_class($header) : gettype($header)
            ));
        }

        if (! preg_match('/^[a-zA-Z0-9\'`#$%&*+.^_|~!-]+$/D', $header)) {
            throw new \InvalidArgumentException(
                sprintf('"%s" is not valid header name.', $header)
            );
        }
    }

    /**
     * Trims whitespace from the header values.
     *
     * Spaces and tabs ought to be excluded by parsers when extracting the field value from a header field.
     *
     * header-field = field-name ":" OWS field-value OWS
     * OWS          = *( SP / HTAB )
     *
     * @param mixed[] $values Header values
     *
     * @return string[] Trimmed header values
     *
     * @see https://tools.ietf.org/html/rfc7230#section-3.2.4
     */
    private function trimAndValidateHeaderValues(array $values): array
    {
        return array_map(function ($value) {
            if (!is_scalar($value) && null !== $value) {
                throw new \InvalidArgumentException(sprintf(
                    'Header value must be scalar or null but %s provided.',
                    is_object($value) ? get_class($value) : gettype($value)
                ));
            }

            $trimmed = trim((string) $value, " \t");
            $this->assertValue($trimmed);

            return $trimmed;
        }, array_values($values));
    }

    /**
     * @see https://tools.ietf.org/html/rfc7230#section-3.2
     *
     * field-value    = *( field-content / obs-fold )
     * field-content  = field-vchar [ 1*( SP / HTAB ) field-vchar ]
     * field-vchar    = VCHAR / obs-text
     * VCHAR          = %x21-7E
     * obs-text       = %x80-FF
     * obs-fold       = CRLF 1*( SP / HTAB )
     */
    private function assertValue(string $value): void
    {
        // The regular expression intentionally does not support the obs-fold production, because as
        // per RFC 7230#3.2.4:
        //
        // A sender MUST NOT generate a message that includes
        // line folding (i.e., that has any field-value that contains a match to
        // the obs-fold rule) unless the message is intended for packaging
        // within the message/http media type.
        //
        // Clients must not send a request with line folding and a server sending folded headers is
        // likely very rare. Line folding is a fairly obscure feature of HTTP/1.1 and thus not accepting
        // folding is not likely to break any legitimate use case.
        if (! preg_match('/^[\x20\x09\x21-\x7E\x80-\xFF]*$/D', $value)) {
            throw new \InvalidArgumentException(
                sprintf('"%s" is not valid header value.', $value)
            );
        }
    }

    /**
     * @param array<string|int, string|string[]> $headers
     */
    private function setHeaders(array $headers): void
    {
        $this->headerNames = $this->headers = [];
        foreach ($headers as $header => $value) {
            // Numeric array keys are converted to int by PHP.
            $header = (string) $header;

            $this->assertHeader($header);
            $value = $this->normalizeHeaderValue($value);
            $normalized = strtolower($header);
            if (isset($this->headerNames[$normalized])) {
                $header = $this->headerNames[$normalized];
                $this->headers[$header] = array_merge($this->headers[$header], $value);
            } else {
                $this->headerNames[$normalized] = $header;
                $this->headers[$header] = $value;
            }
        }
    }

    public function getHeader($header): array
    {
        $header = strtolower($header);

        if (!isset($this->headerNames[$header])) {
            return [];
        }

        $header = $this->headerNames[$header];

        return $this->headers[$header];
    }

    public function getHeaderLine($header): string
    {
        return implode(', ', $this->getHeader($header));
    }

    public function getHeaders(): array
    {
        return $this->headers;
    }

}
