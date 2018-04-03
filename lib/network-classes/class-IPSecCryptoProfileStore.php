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
 * Class IPsecCryptoProfilStore
 * @property $o IPsecCryptoProfil[]
 * @property PANConf $owner
 */
class IPSecCryptoProfileStore extends ObjStore
{
    public static $childn = 'IPSecCryptoProfil';

    protected $fastMemToIndex=null;
    protected $fastNameToIndex=null;

    public function __construct($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
        $this->classn = &self::$childn;
    }

    /**
     * @return IPSecCryptoProfil[]
     */
    public function ipsecCryptoProfil()
    {
        return $this->o;
    }

    /**
     * Creates a new IPsecCryptoProfil in this store. It will be placed at the end of the list.
     * @param string $name name of the new IPsecCryptoProfil
     * @return IPSecCryptoProfil
     */
    public function newIPsecCryptoProfil( $name )
    {
        $CryptoProfile = new IPSecCryptoProfil( $name, $this);
        $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, IPSecCryptoProfil::$templatexml);

        $CryptoProfile->load_from_domxml($xmlElement);

        $CryptoProfile->owner = null;
        $CryptoProfile->setName($name);

        $this->addProfil( $CryptoProfile );

        return $CryptoProfile;
    }

    /**
     * @param IKEGateway $gateway
     * @return bool
     */
    public function addProfil( $CryptoProfile )
    {
        if( !is_object($CryptoProfile) )
            derr('this function only accepts IKEGateway class objects');

        if( $CryptoProfile->owner !== null )
            derr('Trying to add a gateway that has a owner already !');


        $ser = spl_object_hash($CryptoProfile);

        if (!isset($this->fastMemToIndex[$ser]))
        {
            $CryptoProfile->owner = $this;

            if( $this->xmlroot === null )
                $this->createXmlRoot();

            $this->xmlroot->appendChild($CryptoProfile->xmlroot);

            return true;
        } else
            derr('You cannot add a Gateway that is already here :)');

        return false;
    }

    public function createXmlRoot()
    {
        if( $this->xmlroot === null )
        {
            //TODO: 20180331 why I need to create full path? why it is not set before???
            $xml = DH::findFirstElementOrCreate('devices', $this->owner->xmlroot);
            $xml = DH::findFirstElementOrCreate('entry', $xml);
            $xml = DH::findFirstElementOrCreate('network', $xml);
            $xml = DH::findFirstElementOrCreate('ike', $xml);
            $xml = DH::findFirstElementOrCreate('crypto-profiles', $xml);

            $this->xmlroot = DH::findFirstElementOrCreate('ipsec-crypto-profiles', $xml);
        }
    }
} 