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
 * Class IkeCryptoProfil
 * @property IkeCryptoProfileStore $owner
 */
class IkeCryptoProfil
{
    use InterfaceType;
    use XmlConvertible;
    use PathableName;
    use ReferencableObject;

    /** @var null|string[]|DOMElement */
    public $typeRoot = null;

    public $type = 'notfound';

    public $hash = 'notfound';
    public $dhgroup = 'notfound';
    public $encryption = 'notfound';
    public $lifetime_seconds = '';
    public $lifetime_hours = '';

    public $ikecryptoprofiles = Array();


    /**
     * IkeCryptoProfile constructor.
     * @param string $name
     * @param IkeCryptoProfileStore $owner
     */
    public function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
    }

    /**
     * @param DOMElement $xml
     */
    public function load_from_domxml( $xml )
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("tunnel name not found\n");


        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 )
                continue;

            if( $node->nodeName == 'hash' )
                $this->hash = DH::findFirstElementOrCreate('member', $node)->textContent;

            if( $node->nodeName == 'dh-group' )
                $this->dhgroup = DH::findFirstElementOrCreate('member', $node)->textContent;

            if( $node->nodeName == 'encryption' )
                $this->encryption = DH::findFirstElementOrCreate('member', $node)->textContent;

            if( $node->nodeName == 'lifetime' )
            {
                $this->lifetime_seconds = DH::findFirstElement('seconds', $node);
                if( $this->lifetime_seconds == null )
                    $this->lifetime_hours = DH::findFirstElement('hours', $node)->textContent;
                else
                    $this->lifetime_seconds = DH::findFirstElement('seconds', $node)->textContent;
            }
        }
    }

    /**
     * return true if change was successful false if not (duplicate IKECryptoProfil name?)
     * @return bool
     * @param string $name new name for the IKECryptoProfil
     */
    public function setName($name)
    {
        if( $this->name == $name )
            return true;

        /* TODO: 20180331 finalize needed
        if( isset($this->owner) && $this->owner !== null )
        {
            if( $this->owner->isRuleNameAvailable($name) )
            {
                $oldname = $this->name;
                $this->name = $name;
                $this->owner->ruleWasRenamed($this,$oldname);
            }
            else
                return false;
        }
*/
        $this->name = $name;
        $this->xmlroot->setAttribute('name', $name);

        return true;
    }

    public function isIkeCryptoProfilType()
    {
        return true;
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**">
<hash>
  <member>sha1</member>
</hash>
<dh-group>
  <member>group2</member>
</dh-group>
<encryption>
  <member>aes-192-cbc</member>
</encryption>
<lifetime>
  <hours>8</hours>
</lifetime>
</entry>';


}