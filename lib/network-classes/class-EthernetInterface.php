<?php
/*
 * Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
 * Author: Christophe Painchaud <cpainchaud _AT_ paloaltonetworks.com>
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

class EthernetInterface
{
    use InterfaceType;
    use XmlConvertible;
    use PathableName;
    use ReferencableObject;

    /** @var null|DOMElement */
    private $typeRoot = null;

    /** @var EthernetIfStore */
    public $owner;


    /** @var string */
    public $type = 'tmp';

    /** @var string */
    public $description;

    /** @var bool */
    protected $isSubInterface = false;

    /** @var EthernetInterface[] */
    protected $subInterfaces = Array();

    /** @var null|EthernetInterface */
    protected $parentInterface = null;

    /** @var int */
    protected $tag;

    protected $l3ipv4Addresses;

    static public $supportedTypes = Array( 'layer3', 'layer2', 'virtual-wire', 'tap', 'ha', 'aggregate-group' );

    /**
     * @param string $name
     * @param EthernetIfStore $owner
     */
    function EthernetInterface($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
    }

    /**
     * @param DOMElement $xml
     */
    function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("address name not found\n");

        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 )
                continue;

            $nodeName = $node->nodeName;

            if( array_search($nodeName, self::$supportedTypes) !== false )
            {
                $this->type = $nodeName;
                $this->typeRoot = $node;
            }
            elseif( $nodeName == 'comment' )
            {
                $this->description = $node->textContent;
                //print "Desc found: {$this->description}\n";
            }
        }

        if( $this->type == 'tmp' )
        {
            derr('unsupported ethernet interface type : not found', $xml);
        }

        if( $this->type == 'layer3' )
        {
            $this->l3ipv4Addresses = Array();
            $ipNode = DH::findFirstElement('ip', $this->typeRoot);
            if( $ipNode !== false )
            {
                foreach( $ipNode->childNodes as $l3ipNode )
                {
                    if( $l3ipNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $this->l3ipv4Addresses[] = $l3ipNode->getAttribute('name');
                }
            }
        }

        // looking for sub interfaces and stuff like that   :)
        foreach( $this->typeRoot->childNodes as $node )
        {
            if( $node->nodeType != 1 )
                continue;

            // sub interfaces here !
            if( $node->nodeName == 'units' )
            {
                foreach( $node->childNodes as $unitsNode )
                {
                    if( $unitsNode->nodeType != 1 )
                        continue;

                    $newInterface = new EthernetInterface('tmp', $this->owner );
                    $newInterface->isSubInterface = true;
                    $newInterface->parentInterface = $this;
                    $newInterface->type = &$this->type;
                    $newInterface->load_sub_from_domxml($unitsNode);

                    $this->subInterfaces[] = $newInterface;

                }
            }
        }
    }

    /**
     * @param DOMElement $xml
     */
    public function load_sub_from_domxml($xml)
    {
        $this->xmlroot = $xml;
        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("address name not found\n");

        foreach( $xml->childNodes as $node )
        {
            if ($node->nodeType != 1)
                continue;

            $nodeName = $node->nodeName;

            if( $nodeName == 'comment' )
            {
                $this->description = $node->textContent;
                //print "Desc found: {$this->description}\n";
            }
            elseif( $nodeName == 'tag' )
            {
                $this->tag = $node->textContent;
            }
        }

        if( $this->type == 'layer3' )
        {
            if( $this->type == 'layer3' )
            {
                $this->l3ipv4Addresses = Array();
                $ipNode = DH::findFirstElement('ip', $xml);
                if( $ipNode !== false )
                {
                    foreach( $ipNode->childNodes as $l3ipNode )
                    {
                        if( $l3ipNode->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $this->l3ipv4Addresses[] = $l3ipNode->getAttribute('name');
                    }
                }
            }
        }
    }

    /**
     * @return bool
     */
    public function isSubInterface()
    {
        return $this->isSubInterface;
    }

    /**
     * @return string
     */
    public function type()
    {
        return $this->type;
    }

    /**
     * @return int
     */
    public function tag()
    {
        return $this->tag;
    }

    /**
     * @return int
     */
    public function subIfNumber()
    {
        if( !$this->isSubInterface )
            derr('can be called in sub interfaces only');

        $ar = explode('.', $this->name);

        if( count($ar) != 2 )
            derr('unsupported');

        return $ar[1];
    }

    public function getLayer3IPv4Addresses()
    {
        if( $this->type != 'layer3' )
            derr('cannot be requested from a non Layer3 Interface');

        if( $this->l3ipv4Addresses === null )
            return Array();

        return $this->l3ipv4Addresses;
    }

    public function countSubInterfaces()
    {
        return count($this->subInterfaces);
    }

    /**
     * @return EthernetInterface[]
     */
    public function subInterfaces()
    {
        return $this->subInterfaces;
    }

    function isEthernetType() { return true; }

}