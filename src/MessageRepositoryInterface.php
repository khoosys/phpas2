<?php

namespace PHPAS2;

interface MessageRepositoryInterface
{
    /**
     * @param string $id
     *
     * @return null|MessageInterface
     */
    public function findMessageById($id);

    /**
     * @param array $data
     *
     * @return MessageInterface
     */
    public function createMessage($data = []);

    /**
     * @return bool
     */
    public function saveMessage(MessageInterface $message);
}
