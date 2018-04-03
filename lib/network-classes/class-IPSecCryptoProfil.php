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
 * Class IPsecCryptoProfil
 * @property IPSecCryptoProfileStore $owner
 */
class IPSecCryptoProfil
{
    use InterfaceType;
    use XmlConvertible;
    use PathableName;
    use ReferencableObject;

    /** @var null|string[]|DOMElement */
    public $typeRoot = null;

    public $type = 'notfound';

    public $ipsecProtocol = 'notfound';

    public $authentication = 'notfound';
    public $dhgroup = 'notfound';
    public $encryption = 'notfound';
    public $lifetime_seconds = '';
    public $lifetime_minutes = '';
    public $lifetime_hours = '';
    public $lifetime_days = '';

    public $lifesize_kb = '';
    public $lifesize_mb = '';
    public $lifesize_gb = '';
    public $lifesize_tb = '';


    /**
     * IPsecCryptoProfile constructor.
     * @param string $name
     * @param IPSecCryptoProfileStore $owner
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

            if( $node->nodeName == 'esp' )
            {
                $this->ipsecProtocol = 'esp';
                $tmp_authentication = DH::findFirstElementOrCreate('authentication', $node);
                $this->authentication = DH::findFirstElementOrCreate('member', $tmp_authentication)->textContent;

                $tmp_encryption = DH::findFirstElementOrCreate('encryption', $node);
                $this->encryption = DH::findFirstElementOrCreate('member', $tmp_encryption)->textContent;
            }

            if( $node->nodeName == 'ah' )
            {
                $this->ipsecProtocol = 'ah';
                $tmp_authentication = DH::findFirstElementOrCreate('authentication', $node);
                $this->authentication = DH::findFirstElementOrCreate('member', $tmp_authentication)->textContent;
            }

            if( $node->nodeName == 'lifetime' )
            {
                if( DH::findFirstElement('seconds', $node) != null )
                    $this->lifetime_seconds = DH::findFirstElement('seconds', $node)->textContent;
                elseif( DH::findFirstElement('minutes', $node) != null )
                    $this->lifetime_minutes = DH::findFirstElement('minutes', $node)->textContent;
                elseif( DH::findFirstElement('hours', $node) != null )
                    $this->lifetime_hours = DH::findFirstElement('hours', $node)->textContent;
                elseif( DH::findFirstElement('days', $node) != null )
                    $this->lifetime_days = DH::findFirstElement('days', $node)->textContent;
            }

            if( $node->nodeName == 'lifesize' )
            {
                if( DH::findFirstElement('kb', $node) != null )
                    $this->lifesize_kb = DH::findFirstElement('kb', $node)->textContent;
                elseif( DH::findFirstElement('mb', $node) != null )
                    $this->lifesize_mb = DH::findFirstElement('mb', $node)->textContent;
                elseif( DH::findFirstElement('gb', $node) != null )
                    $this->lifesize_gb = DH::findFirstElement('gb', $node)->textContent;
                elseif( DH::findFirstElement('tb', $node) != null )
                    $this->lifesize_tb = DH::findFirstElement('tb', $node)->textContent;
            }

            if( $node->nodeName == 'dh-group' )
                $this->dhgroup = $node->textContent;
        }
    }

    /**
     * return true if change was successful false if not (duplicate IPsecCryptoProfil name?)
     * @return bool
     * @param string $name new name for the IPsecCryptoProfil
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

    public function setIPsecDHgroup( $dggroup )
    {
        if( $this->$dggroup == $dggroup )
            return true;

        $this->gateway = $dggroup;

        $tmp_ipsec_entry = DH::findFirstElementOrCreate('esp', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate('dh-group', $tmp_ipsec_entry);
        DH::setDomNodeText( $tmp_gateway, $dggroup);


        return true;
    }
    /*
        * * <dh-group>group2</dh-group>
         * esp / ah
         * <esp>
              <authentication>
                <member>sha256</member>
              </authentication>
         * sha-1

         * <esp>
      <authentication>
        <member>sha256</member>
      </authentication> 8
        * <lifetime>
          <hours>1</hours>
        </lifetime>
        * second 3600 / hour
     */

    public function isIPsecCryptoProfilType()
    {
        return true;
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**">
<esp>
  <authentication>
    <member>sha256</member>
  </authentication>
  <encryption>
    <member>aes-128-gcm</member>
  </encryption>
</esp>
<lifetime>
  <hours>1</hours>
</lifetime>
<dh-group>group2</dh-group>
</entry>';
}