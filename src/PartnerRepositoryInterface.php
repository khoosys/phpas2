<?php

namespace PHPAS2;

interface PartnerRepositoryInterface
{
    /**
     * @param string $id
     *
     * @return null|PartnerInterface
     */
    public function findPartnerById($id);
}
