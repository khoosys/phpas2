<?php

namespace PHPAS2\Tests;

use PHPAS2\Management;
use PHPAS2\MessageRepositoryInterface;
use PHPAS2\PartnerRepositoryInterface;
use PHPAS2\Tests\Mock\MessageRepository;
use PHPAS2\Tests\Mock\PartnerRepository;

abstract class TestCase extends \PHPUnit\Framework\TestCase
{
    /**
     * @var Management
     */
    protected $management;

    /**
     * @var PartnerRepositoryInterface
     */
    protected $partnerRepository;

    /**
     * @var MessageRepositoryInterface
     */
    protected $messageRepository;

    protected function loadFixture($name)
    {
        return file_get_contents(__DIR__.DIRECTORY_SEPARATOR.'fixtures'.DIRECTORY_SEPARATOR.$name);
    }

    protected function getCerts($file = 'phpas2.p12')
    {
        $certs = [];
        $pkcs12 = $this->loadFixture($file);
        openssl_pkcs12_read($pkcs12, $certs, null);

        return $certs;
    }

    protected function initMessage($file = 'test.edi')
    {
        $body = $this->loadFixture($file);

        return "Content-type: application/EDI-Consent\r\nContent-Transfer-Encoding: binary\r\nContent-Disposition: attachment; filename=payload.txt\r\n\r\n$body";

        // return new MimePart(
        //     [
        //         'Content-type' => 'application/EDI-Consent',
        //         'Content-Transfer-Encoding' => 'binary',
        //         'Content-Disposition' => 'attachment; filename=payload.txt',
        //     ], $this->loadFixture($file)
        // );
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->partnerRepository = new PartnerRepository();
        $this->messageRepository = new MessageRepository();
        $this->management = new Management();
    }
}
