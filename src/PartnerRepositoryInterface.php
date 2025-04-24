<?php

namespace AS2;

interface PartnerRepositoryInterface
{
    /**
     * @param string $id
     *
     * @return null|PartnerInterface
     */
    public function findPartnerById($id);
}
