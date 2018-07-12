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
 * Class IPsecTunnel
 * @property IPsecTunnelStore $owner
 */
class IPsecTunnel
{
    use InterfaceType;
    use XmlConvertible;
    use PathableName;
    use ReferencableObject;

    /** @var null|string[]|DOMElement */
    public $typeRoot = null;
    /** @var null|string[]|DOMElement */
    public $proxyIdRoot = null;

    /** @var null|string[]|DOMElement */
    public $proxyIdRootv6 = null;

    public $type = 'notfound';

    /** @var null|string[]|DOMElement */
    public $gateway = 'notfound';

    /** @var null|string[]|DOMElement */
    public $protocol = 'notfound';
    /** @var null|string[]|DOMElement */
    public $protocol_local = 'notfound';
    /** @var null|string[]|DOMElement */
    public $protocol_remote = 'notfound';

    public $proxys = Array();

    public $proposal = null;
    public $interface = null;
    public $localIP = null;
    public $remoteIP = null;

    /**
     * IPsecTunnel constructor.
     * @param string $name
     * @param IPsecTunnelStore $owner
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

            if( $node->nodeName == 'auto-key' )
            {
                $this->type = 'auto-key';
                $this->typeRoot = $node;
                //print "found type auto key\n";

                // now extracts IPSEC tunnel name
                $tmp_gateway = DH::findFirstElementOrCreate('ike-gateway', $node);
                $tmp_gateway_entry = DH::findFirstElementOrCreate('entry', $tmp_gateway);
                $this->gateway = DH::findAttribute('name', $tmp_gateway_entry);
                if( $this->gateway === FALSE )
                    derr("ike-gateway not found\n");

                $tmp_proposal = DH::findFirstElementOrCreate('ipsec-crypto-profile', $node);
                $this->proposal = $tmp_proposal->textContent;

                // now extracts ProxyID
                $this->proxyIdRoot = DH::findFirstElementOrCreate('proxy-id', $node);

                // now extracts ProxyID for IPv6
                $this->proxyIdRootv6 = DH::findFirstElementOrCreate('proxy-id-v6', $node);

                foreach( $this->proxyIdRoot->childNodes as $proxyNode )
                {
                    if( $proxyNode->nodeType != 1 )
                        continue;

                    $proxyName = DH::findAttribute('name', $proxyNode);

                    $local = DH::findFirstElement('local', $proxyNode);
                    if( $local !== false )
                        $local = $local->nodeValue;
                    else
                        $local = '0.0.0.0/0';
                    
                    $remote = DH::findFirstElement('remote', $proxyNode);
                    if( $remote !== false )
                        $remote = $remote->nodeValue;
                    else
                        $remote = '0.0.0.0/0';

                    $protocolNode = DH::findFirstElement('protocol', $proxyNode);
                    if( $protocolNode )
                    {
                        $protocol_tcp = DH::findFirstElement('tcp', $protocolNode);
                        $protocol_udp = DH::findFirstElement('udp', $protocolNode);
                        $protocol_number = DH::findFirstElement('number', $protocolNode);
                        $protocol_any = DH::findFirstElement('any', $protocolNode);
                    }
                    else
                    {
                        $protocolNode = DH::findFirstElementOrCreate('protocol', $proxyNode);
                        $protocol_any = DH::findFirstElementOrCreate('any', $protocolNode);
                        $protocol_tcp = false;
                        $protocol_udp = false;
                        $protocol_number = false;
                    }



                    if( $protocol_tcp !== FALSE )
                    {
                        $protocol = "tcp";
                        $protocol_ports = $protocol_tcp;
                    }
                    elseif( $protocol_udp !== FALSE )
                    {
                        $protocol = "udp";
                        $protocol_ports = $protocol_udp;
                    }
                    elseif( $protocol_number !== FALSE )
                    {
                        $protocol = "number";
                        $protocol_ports = null;

                        $localport = $protocol_number->nodeValue;
                        $remoteport = $localport;

                    }
                    elseif( $protocol_any !== FALSE )
                    {
                        $protocol = "any";
                        $protocol_ports = null;
                        $localport = '';
                        $remoteport = '';
                    }

                    if( $protocol_ports !== null )
                    {
                        $localport = DH::findFirstElement('local-port', $protocol_ports);
                        if( $localport !== false )
                            $localport = $localport->nodeValue;
                        else
                            $localport = '';

                        $remoteport = DH::findFirstElement('remote-port', $protocol_ports);
                        if( $remoteport !== false )
                            $remoteport = $remoteport->nodeValue;
                        else
                            $remoteport = '';
                    }


                    $protocol_array = array();
                    $protocol_array['type'] = $protocol;
                    $protocol_array['localport'] = $localport;
                    $protocol_array['remoteport'] = $remoteport;


                    $record = Array('name' => $proxyName ,'local' => $local, 'remote' => $remote, 'xmlroot' => $proxyNode, 'protocol' => $protocol_array, 'type' => 'IPv4' );

                    $this->proxys[] = &$record;
                    unset($record);
                }



                foreach( $this->proxyIdRootv6->childNodes as $proxyNode )
                {
                    if( $proxyNode->nodeType != 1 )
                        continue;

                    $proxyName = DH::findAttribute('name', $proxyNode);

                    $local = DH::findFirstElement('local', $proxyNode);
                    if( $local !== false )
                        $local = $local->nodeValue;
                    else
                        $local = '::';

                    $remote = DH::findFirstElement('remote', $proxyNode);
                    if( $remote !== false )
                        $remote = $remote->nodeValue;
                    else
                        $remote = '::';

                    $protocolNode = DH::findFirstElement('protocol', $proxyNode);
                    if( $protocolNode )
                    {
                        $protocol_tcp = DH::findFirstElement('tcp', $protocolNode);
                        $protocol_udp = DH::findFirstElement('udp', $protocolNode);
                        $protocol_number = DH::findFirstElement('number', $protocolNode);
                        $protocol_any = DH::findFirstElement('any', $protocolNode);
                    }
                    else
                    {
                        $protocolNode = DH::findFirstElementOrCreate('protocol', $proxyNode);
                        $protocol_any = DH::findFirstElementOrCreate('any', $protocolNode);
                        $protocol_tcp = false;
                        $protocol_udp = false;
                        $protocol_number = false;
                    }


                    if( $protocol_tcp !== FALSE )
                    {
                        $protocol = "tcp";
                        $protocol_ports = $protocol_tcp;
                    }
                    elseif( $protocol_udp !== FALSE )
                    {
                        $protocol = "udp";
                        $protocol_ports = $protocol_udp;
                    }
                    elseif( $protocol_number !== FALSE )
                    {
                        $protocol = "number";
                        $protocol_ports = null;

                        $localport = $protocol_number->nodeValue;
                        $remoteport = $localport;

                    }
                    elseif( $protocol_any !== FALSE )
                    {
                        $protocol = "any";
                        $protocol_ports = null;
                        $localport = '';
                        $remoteport = '';
                    }

                    if( $protocol_ports !== null )
                    {
                        $localport = DH::findFirstElement('local-port', $protocol_ports);
                        if( $localport !== false )
                            $localport = $localport->nodeValue;
                        else
                            $localport = '';

                        $remoteport = DH::findFirstElement('remote-port', $protocol_ports);
                        if( $remoteport !== false )
                            $remoteport = $remoteport->nodeValue;
                        else
                            $remoteport = '';
                    }

                    $protocol_array = array();
                    $protocol_array['type'] = $protocol;
                    $protocol_array['localport'] = $localport;
                    $protocol_array['remoteport'] = $remoteport;


                    $record = Array('name' => $proxyName ,'local' => $local, 'remote' => $remote, 'xmlroot' => $proxyNode, 'protocol' => $protocol_array, 'type' => 'IPv6' );

                    $this->proxys[] = &$record;
                    unset($record);
                }
            }


            if( $node->nodeName == 'tunnel-interface' )
            {
                $this->interface = $node->textContent;
            }
        }
    }

    /**
     * line structure: Array('local' => $local->nodeValue, 'remote' => $remote->nodeValue, 'xmlroot' => $proxyNode );
     * @return string[][]
     */
    public function proxyIdList()
    {
        return $this->proxys;
    }

    /**
     * @param string $local
     * @param string $remote
     * @return string[]|null
     */
    public function searchProxyIdLine( $local, $remote)
    {
        foreach($this->proxys as &$proxy )
        {
            if( $proxy['local'] == $local && $proxy['remote'] == $remote )
                return $proxy;
        }

        return null;
    }

    /**
     * @param string $local
     * @param string $remote
     * @return bool
     */
    public function hasProxyId( $local, $remote)
    {
        $ret = $this->searchProxyIdLine($local, $remote);

        if( $ret === null )
            return false;

        return true;
    }

    /**
     * @param string $baseName
     * @return string
     */
    public function findAvailableProxyIdName($baseName)
    {
        $tmp_proxy = $this->proxys;
        for($i=0; $i<10000; $i++)
        {
            $newName = $baseName.$i;

            if( count( $tmp_proxy ) == 0 )
                return $newName;

            foreach($tmp_proxy as $id => $proxy )
            {
                if( $proxy['name'] == $newName )
                {
                    unset( $tmp_proxy[$id] );
                    break;
                }
            }
        }

        derr("this should never happen");
    }


    /**
     * @param string $local
     * @param string $remote
     * @return bool
     */
    function removeProxyId($local, $remote)
    {
        foreach($this->proxys as $index => &$proxy )
        {
            if( $proxy['local'] == $local && $proxy['remote'] == $remote )
            {
                unset($this->proxys[$index]);
                $this->proxyIdRoot->removeChild($proxy['xmlroot']);
                return true;
            }
        }
        return false;
    }


    /**
     * @param string $local
     * @param string $remote
     * @param null|string $name
     * @return bool
     */
    public function addProxyId( $local, $remote, $name=null )
    {
        if( $name === null )
            $name = $this->findAvailableProxyIdName('proxy-');

        foreach($this->proxys as &$proxy )
        {
            if( $proxy['local'] == $local && $proxy['remote'] == $remote )
                return false;
        }

        $newRoot = DH::createElement($this->proxyIdRoot, 'entry');
        $newRoot->setAttribute('name', $name);

        DH::createElement($newRoot, 'local', $local);
        DH::createElement($newRoot, 'remote', $remote);

        $tmp_protocol = DH::createElement($newRoot, 'protocol');
        DH::createElement($tmp_protocol, 'any');

        $newArray = Array('name' => $name, 'local' => $local, 'remote' => $remote, 'xmlroot' => $newRoot);

        $this->proxys[] = &$newArray;

        return true;
    }

    /**
     * return true if change was successful false if not (duplicate IPsectunnel name?)
     * @return bool
     * @param string $name new name for the IPsecTunnel
     */
    public function setName($name)
    {
        if( $this->name == $name )
            return true;

        if( preg_match( '/[^0-9a-zA-Z_\-\s]/' , $name ) )
        {
            $name = preg_replace('/[^0-9a-zA-Z_\-\s]/',"", $name);
            print " *** new name: ".$name." \n";
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

    public function setIKEGateway( $gateway_name )
    {
        if( $this->gateway == $gateway_name )
            return true;

        if( preg_match( '/[^0-9a-zA-Z_\-\s]/' , $gateway_name ) )
        {
            $gateway_name = preg_replace('/[^0-9a-zA-Z_\-\s]/',"", $gateway_name);
            print " *** new Gateway name: ".$gateway_name."\n";
            #mwarning( 'Name will be replaced with: '.$gateway_name."\n" );
        }

        $this->gateway = $gateway_name;

        $tmp_ipsec_entry = DH::findFirstElementOrCreate('auto-key', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate('ike-gateway', $tmp_ipsec_entry);
        $tmp_gateway_entry = DH::findFirstElementOrCreate('entry', $tmp_gateway);
        $tmp_gateway_entry->setAttribute('name', $gateway_name);

        return true;
    }

    public function setProposal( $proposal )
    {
        if( $this->proposal == $proposal )
            return true;

        if( preg_match( '/[^0-9a-zA-Z_\-\s]/' , $proposal ) )
        {
            $proposal = preg_replace('/[^0-9a-zA-Z_\-\s]/',"", $proposal);
            print " *** new proposal name: ".$proposal."\n";
            mwarning( 'Name will be replaced with: '.$proposal."\n" );
        }
        
        $this->proposal = $proposal;

        $tmp_ipsec_entry = DH::findFirstElementOrCreate('auto-key', $this->xmlroot);
        $tmp_gateway = DH::findFirstElementOrCreate('ipsec-crypto-profile', $tmp_ipsec_entry);
        DH::setDomNodeText( $tmp_gateway, $proposal);

        return true;
    }

    public function setInterface( $interface )
    {
        if( $this->interface == $interface )
            return true;

        $this->interface = $interface;

        $tmp_ipsec_entry = DH::findFirstElementOrCreate('tunnel-interface', $this->xmlroot);
        DH::setDomNodeText( $tmp_ipsec_entry, $interface);

        return true;
    }


    public function isIPsecTunnelType() { return true; }

    static public $templatexml = '<entry name="**temporarynamechangeme**">
              <auto-key>
                <ike-gateway>
                  <entry name="**temporaryIKEGateway**"/>
                </ike-gateway>
                <ipsec-crypto-profile>default</ipsec-crypto-profile>
                <proxy-id></proxy-id>
              </auto-key>
              <tunnel-monitor>
                <enable>no</enable>
              </tunnel-monitor>
              <tunnel-interface></tunnel-interface>
              <anti-replay>yes</anti-replay>
              <copy-tos>no</copy-tos>
    </entry>';

}