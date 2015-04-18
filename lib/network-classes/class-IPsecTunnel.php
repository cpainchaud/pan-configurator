<?php

/*
 * Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
 * Author: Christophe Painchaud cpainchaud _AT_ paloaltonetworks.com
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


class IPsecTunnel
{
    use InterfaceType;
    use XmlConvertible;
    use PathableName;
    use ReferencableObject;


    /**
     * @var null|string[]|DOMElement
     */
    public $typeRoot = null;
    /**
     * @var null|string[]|DOMElement
     */
    public $proxyIdRoot = null;

    public $type = 'notfound';

    public $proxys = Array();


    public function IPsecTunnel($name, $owner)
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

                // now extracts ProxyID
                $this->proxyIdRoot = DH::findFirstElementOrCreate('proxy-id', $node);

                foreach( $this->proxyIdRoot->childNodes as $proxyNode )
                {
                    if( $proxyNode->nodeType != 1 )
                        continue;


                    $local = DH::findFirstElementOrDie('local', $proxyNode);
                    $remote = DH::findFirstElementOrDie('remote', $proxyNode);
                    $proxyName = DH::findAttribute('name', $proxyNode);

                    $record = Array('name' => $proxyName ,'local' => $local->nodeValue, 'remote' => $remote->nodeValue, 'xmlroot' => $proxyNode );

                    $this->proxys[] = &$record;
                    unset($record);
                }
            }

        }
    }

    /**
     * line structure: Array('local' => $local->nodeValue, 'remote' => $remote->nodeValue, 'xmlroot' => $proxyNode );
     * @return string[][]
     */
    public function proxyIdList()
    {
        $this->proxys;
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
        for($i=0; $i<10000; $i++)
        {
            $newName = $baseName.$i;

            foreach($this->proxys as &$proxy )
            {
                if( $proxy['name'] == $newName )
                    break;
            }
            return $newName;
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
    public function addProxyId( $local, $remote, $name=null)
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

        $newArray = Array('name' => $name, 'local' => $local, 'remote' => $remote, 'xmlroot' => $newRoot);

        $this->proxys[] = &$newArray;

        return true;
    }

    public function isIPsecTunnelType() { return true; }

}