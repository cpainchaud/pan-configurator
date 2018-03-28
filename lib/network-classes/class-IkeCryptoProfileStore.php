<?php

/*
 * Copyright (c) 2014-2017 Christophe Painchaud <shellescape _AT_ gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.

 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

/**
 * Class IkeCryptoProfilStore
 * @property $o IkeCryptoProfil[]
 * @property PANConf $owner
 */
class IkeCryptoProfileStore extends ObjStore
{
    public static $childn = 'IkeCryptoProfil';

    public function __construct($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
        $this->classn = &self::$childn;
    }

    /**
     * @return IkeCryptoProfil[]
     */
    public function ikeCryptProfil()
    {
        return $this->o;
    }


    /**
     * @param $name
     * @param null $ref
     * @param bool $nested
     * @return null|IkeCryptoProfil
     */
    public function find($name, $ref=null, $nested = true)
    {
        $f = $this->findByName($name,$ref);

        if( $f !== null )
            return $f;

        if( $nested && $this->parentCentralStore !== null )
            return $this->parentCentralStore->find( $name, $ref, $nested);

        return null;
    }


    /**
     * @param $name string
     * @param $type string
     * @param $value string
     * @param string $description
     * @return Address
     * @throws Exception
     */
    public function newIkeCryptoProfil($name , $type, $value, $description = '')
    {
        $found = $this->find($name,null, true);
        if( $found !== null )
            derr("cannot create Address named '".$name."' as this name is already in use");

        $newObject = new Address($name,$this, true);
        $newObject->setType($type);
        $newObject->setValue($value);
        $newObject->setDescription($description);

        $this->add($newObject);

        return $newObject;
    }

} 