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

    public $proposal = '';

    public $version = '';

    public $natTraversal = '';
    public $fragmentation = '';

    public $localAddress = false;
    public $localInterface = false;
    public $peerAddress = false;

    public $localID = false;
    public $peerID = false;

    public $localIDtype = false;
    public $peerIDtype = false;

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

        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 )
                continue;

            if( $node->nodeName == 'authentication' )
            {
                $tmp_psk = DH::findFirstElement('pre-shared-key' , $node);
                if( $tmp_psk != null )
                    $this->preSharedKey = DH::findFirstElementOrCreate('key', $tmp_psk)->textContent;
            }

            if( $node->nodeName == 'local-address' )
            {
                $this->localInterface = DH::findFirstElementOrCreate('interface', $node)->textContent;
            }

            if( $node->nodeName == 'peer-address' )
            {
                $this->peerAddress = DH::findFirstElementOrCreate('ip', $node)->textContent;
            }


            if( $node->nodeName == 'protocol' )
            {
                $this->version =  DH::findFirstElementOrCreate('version', $node)->textContent;
                if( $this->version == null )
                    $this->version = "ikev1";

                $tmp_ikevX = $this->proposal = DH::findFirstElement($this->version, $node);
                if( $tmp_ikevX != null )
                    $this->proposal = DH::findFirstElementOrCreate('ike-crypto-profile', $tmp_ikevX)->textContent;

                if( $this->proposal == null )
                    $this->proposal = "default";
            }

            if( $node->nodeName == 'protocol-common' )
            {
                $tmp_natT = DH::findFirstElementOrCreate( 'nat-traversal', $node);
                if( $tmp_natT != null )
                    $this->natTraversal = DH::findFirstElementOrCreate('enable', $tmp_natT)->textContent;

                $tmp_frag = DH::findFirstElementOrCreate( 'fragmentation', $node);
                if( $tmp_frag != null )
                    $this->fragmentation = DH::findFirstElementOrCreate('enable', $tmp_frag)->textContent;
            }

            if( $node->nodeName == 'local-id' )
            {
                $this->localID =  DH::findFirstElementOrCreate('id', $node)->textContent;
                $this->localIDtype = DH::findFirstElementOrCreate('type', $node)->textContent;
            }

            if( $node->nodeName == 'peer-id' )
            {
                $this->peerID = DH::findFirstElementOrCreate('id', $node)->textContent;
                $this->peerIDtype = DH::findFirstElementOrCreate('type', $node)->textContent;
            }


            if( $node->nodeName == 'disabled' )
                $this->disabled = $node->textContent;
        }
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

        if( preg_match( '[^\d]', $name ) )
        {
            //NO digit allowed at the beginning of a name
            derr( 'no digit allowed at the beginning of a IKE gateway name' );
        }

        if( preg_match( '/[^0-9a-zA-Z_\-]/' , $name ) )
        {
            //NO blank allowed in gateway name
            //NO other characters are allowed as seen here
            $name = preg_replace('/[^0-9a-zA-Z_\-]/',"", $name);
            print " *** new gateway name: ".$name." \n";
            #mwarning( 'Name will be replaced with: '.$name."\n" );
        }




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

    public function setproposal( $proposal )
    {
        if( $this->proposal == $proposal )
            return true;

        $this->proposal = $proposal;

        $tmp_gateway = DH::findFirstElementOrCreate('protocol', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate( $this->version, $tmp_gateway);
        $tmp_gateway = DH::findFirstElementOrCreate( 'ike-crypto-profile', $tmp_gateway);
        DH::setDomNodeText( $tmp_gateway, $proposal);

        return true;
    }
    
    public function setinterface( $interface )
    {
        if( $this->localInterface == $interface )
            return true;

        $this->localInterface = $interface;

        $tmp_gateway = DH::findFirstElementOrCreate('local-address', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate('interface', $tmp_gateway);
        DH::setDomNodeText( $tmp_gateway, $interface);

        return true;
    }

    public function setpeerAddress( $peeraddress )
    {
        if( $this->peerAddress == $peeraddress )
            return true;

        $this->peerAddress = $peeraddress;

        $tmp_gateway = DH::findFirstElementOrCreate('peer-address', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate('ip', $tmp_gateway);
        DH::setDomNodeText( $tmp_gateway, $peeraddress);

        return true;
    }

    public function setPreSharedKey( $presharedkey )
    {
        if( $this->preSharedKey == $presharedkey )
            return true;

        $this->preSharedKey = $presharedkey;

        $tmp_gateway = DH::findFirstElementOrCreate('authentication', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate( 'pre-shared-key', $tmp_gateway);
        $tmp_gateway = DH::findFirstElementOrCreate( 'key', $tmp_gateway);
        DH::setDomNodeText( $tmp_gateway, $presharedkey);

        return true;
    }

    /**
     * @param $newType string
     * @return bool true if successful
     */
    public function API_setPreSharedKey( $presharedkey )
    {
        if( !$this->setPreSharedKey( $presharedkey ) )
            return false;

        $c = findConnectorOrDie($this);

        #$xpath = $this->getXPath();
        $tmp_gateway = DH::findFirstElementOrCreate('authentication', $this->xmlroot);
        $xpath = DH::findFirstElementOrCreate( 'pre-shared-key', $tmp_gateway);
        $xpath = $xpath->getNodePath();

        $element = "<key>".$presharedkey."</key>";

        $c->sendSetRequest($xpath,  $element );

        $this->setPreSharedKey( $presharedkey );

        return true;
    }
    //TODO: create set functions for:
    //set nat-traversal
    //set dpd


    public function isIKEGatewayType() { return true; }

    //"-AQ==A4vEGnxsZCP7poqzjhJD4Gc+tbE=DS4xndFfZiigUHPCm4ASFQ==" => "DEMO"
    //"-AQ==2WmDHripnP+MAuaB9DKJ5dPWlmQ=wgoOihqVrKK2NmxerTkFKg==" => 'temp'
    static public $templatexml = '<entry name="**temporarynamechangeme**">
    <authentication>
        <pre-shared-key>
            <key>-AQ==A4vEGnxsZCP7poqzjhJD4Gc+tbE=DS4xndFfZiigUHPCm4ASFQ==</key>
        </pre-shared-key>
    </authentication>
    <protocol>
        <ikev1><dpd><enable>yes</enable><interval>5</interval><retry>5</retry></dpd><ike-crypto-profile>default</ike-crypto-profile><exchange-mode>auto</exchange-mode></ikev1>
        <ikev2><dpd><enable>yes</enable><interval>5</interval></dpd><ike-crypto-profile>default</ike-crypto-profile></ikev2>
        <version>ikev1</version>
      </protocol>
    <protocol-common><nat-traversal><enable>no</enable></nat-traversal><fragmentation><enable>no</enable></fragmentation></protocol-common>
    <local-address><interface></interface></local-address>
    <peer-address><ip></ip></peer-address>
    <disabled>no</disabled>
</entry>';

}