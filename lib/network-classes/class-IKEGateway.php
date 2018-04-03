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
 * Class IKEGateway
 * @property IKEGatewayStore $owner
 */
class IKEGateway
{
    use InterfaceType;
    use XmlConvertible;
    use PathableName;
    use ReferencableObject;

    /** @var null|string[]|DOMElement */
    public $typeRoot = null;

    public $type = 'notfound';

    public $preSharedKey = '';

    public $natTraversel = '';
    public $fragmentation = '';

    public $localAddress = false;
    public $peerAddress = false;
    public $localID = false;
    public $peerID = false;
    public $disabled = false;

    /**
     * IKEGateway constructor.
     * @param string $name
     * @param IKEGatewayStore $owner
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

        /* EXAMPLE
         <gateway>
            <entry name="test_GW">
         <authentication>
                <pre-shared-key>
                  <key>-AQ==qUqP5cyxm6YcTAhz05Hph5gvu9M=2Hdt3i//3KRNmATVQFFopQ==</key>
                </pre-shared-key>
              </authentication>

         <protocol>
                <ikev1>
                  <dpd>
                    <enable>yes</enable>
                    //if enabled and interval / retry not availalbe value is 5
                    <interval>10</interval>
                    <retry>10</retry>
                  </dpd>
                //set to default is not availalbe
                <ike-crypto-profile>Suite-B-GCM-128</ike-crypto-profile>
                //set to auto if not available
                  <exchange-mode>main</exchange-mode>
                </ikev1>
                <ikev2>
                  <dpd>
                    <enable>yes</enable>
                    //only interval available
                    <interval>10</interval>
                  </dpd>
                //set to default if not available
                  <ike-crypto-profile>Suite-B-GCM-128</ike-crypto-profile>
                  <require-cookie>yes</require-cookie>
                </ikev2>
                <version>ikev1</version>
              </protocol>

         <protocol-common>
                <nat-traversal>
                  <enable>no</enable>
                </nat-traversal>
                <fragmentation>
                  <enable>no</enable>
                </fragmentation>
              </protocol-common>

        <local-address>
                <interface>ethernet1/1</interface>
              </local-address>

         <peer-address>
                <ip>4.4.2.2</ip>
              </peer-address>

         <local-id>
                <id>test.test.de</id>
                <type>fqdn</type>
              </local-id>
         <peer-id>
                <id>1.1.1.1</id>
                <type>ipaddr</type>
              </peer-id>

         <disabled>yes</disabled>
            </entry>
          </gateway>
         */

        /*
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
        */
    }

    /**
     * return true if change was successful false if not (duplicate rulename?)
     * @return bool
     * @param string $name new name for the rule
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

    public function isIKEGatewayType() { return true; }

    static public $templatexml = '<entry name="**temporarynamechangeme**">
    <authentication><pre-shared-key><key></key></pre-shared-key></authentication>
    <protocol>
        <ikev1><dpd><enable>yes</enable><interval>5</interval><retry>5</retry></dpd><ike-crypto-profile>default</ike-crypto-profile><exchange-mode>auto</exchange-mode></ikev1>
        <ikev2><dpd><enable>yes</enable><interval>5</interval></dpd><ike-crypto-profile>default</ike-crypto-profile></ikev2>
        <version>ikev1</version>
      </protocol>
    <protocol-common><nat-traversal><enable>no</enable></nat-traversal><fragmentation><enable>no</enable></fragmentation></protocol-common>
    <local-address><interface></interface></local-address>
    <peer-address><ip></ip></peer-address>
    <local-id></local-id>
    <peer-id></peer-id>
    <disabled>no</disabled>
</entry>';

}