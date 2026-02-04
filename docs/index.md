# DOCUMENTATION

Please have a look at an example application based on Slim3 framework.

You can also create your own classes.

- Implement MessageRepository class based on \PHPAS2\MessageRepositoryInterface
- Implement Message class based on \PHPAS2\MessageInterface
- Implement PartnerRepository class based on \PHPAS2\PartnerRepositoryInterface
- Implement Partner class based on \PHPAS2\PartnerInterface

### Example Receive AS2 Message
```php
$manager = new \PHPAS2\Management();

/** @var /PHPAS2/MessageRepositoryInterface $messageRepository */
$messageRepository = new App\Repositories\MessageRepository();

/** @var /PHPAS2/PartnerRepositoryInterface $partnerRepository */
$partnerRepository = new App\Repositories\PartnerRepository();

$server = new \PHPAS2\Server($manager, $partnerRepository, $messageRepository);

/** @var \GuzzleHttp\Psr7\Response $response */
$response = $server->excecute();
```

### Example Send AS2 Message
```php

$manager = new \PHPAS2\Management();

//loading conf files
$partners          = require __DIR__ . '/config/partners.php';

/** @var /PHPAS2/MessageRepositoryInterface $messageRepository */
$messageRepository = new App\Repositories\MessageRepository(['path' => $storagePath . DIRECTORY_SEPARATOR . 'sent']);

/** @var /PHPAS2/PartnerRepositoryInterface $partnerRepository */
$partnerRepository = new App\Repositories\PartnerRepository($partners);

// Init partners
$sender = $partnerRepository->findPartnerById('A');
$receiver = $partnerRepository->findPartnerById('B');

// Generate new message ID
$messageId = \PHPAS2\Utils::generateMessageID($sender);
$rawMessage = '
Content-type: Application/EDI-X12
Content-disposition: attachment; filename=payload
Content-id: <test@test.com>

ISA*00~';

// Init new Message
$message = $messageRepository->createMessage();
$message->setMessageId($messageId);
$message->setSender($sender);
$message->setReceiver($receiver);

$payload = $manager->buildMessage($message, $rawMessage);
if ($response = $manager->sendMessage($message, $payload)){
    echo "OK \n";
}

$messageRepository->saveMessage($message);

```
