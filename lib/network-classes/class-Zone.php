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
class Zone
{

	use ReferencableObject;
	use PathableName;
    use XmlConvertible;

    /**
     * @var null|ZoneStore
     */
    public $owner = null;
	
	private $isTmp = true;

    /**
     * @var null|string[]|DOMNode
     */
    public $xmlroot = null;


    /**
     * @var string[]
     */
    private $attachedInterfaces = Array();


    const TypeTmp = 0;
    const TypeLayer3 = 1;

    static private $ZoneTypes = Array(self::TypeTmp => 'tmp',
        self::TypeLayer3 => 'layer3',
         );


    /**
     * @param string $name
     * @param ZoneStore|null $owner
     */
 	public function Zone($name, $owner, $fromXmlTemplate = false)
 	{
 		$this->owner = $owner;


        if( $fromXmlTemplate )
        {
            $doc = new DOMDocument();
            $doc->loadXML(self::$templatexml);

            $node = DH::findFirstElementOrDie('entry',$doc);

            $rootDoc = $this->owner->xmlroot->ownerDocument;
            $this->xmlroot = $rootDoc->importNode($node, true);
            $this->load_from_domxml($this->xmlroot);

            $this->setName($name);
        }

		$this->name = $name;
 	}

    /**
     * @param string $newName
     */
 	public function setName($newName)
 	{
        $ret = $this->setRefName($newName);

        if( $this->xmlroot === null )
            return $ret;

        $this->xmlroot->getAttributeNode('name')->nodeValue = $newName;

        return $ret;
    }

    public function isTmp()
    {
        return $this->isTmp;
    }


    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;
        $this->isTmp = false;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("zone name not found\n", $xml);

        if( strlen($this->name) < 1  )
            derr("Zone name '".$this->name."' is not valid", $xml);

        $networkNode = DH::findFirstElementOrDie('network', $xml);

        foreach( $networkNode->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            if( $node->tagName == 'layer3')
            {
                $this->type = 'layer3';

                foreach( $node->childNodes as $ifNode )
                {
                    if( $ifNode->nodeType != XML_ELEMENT_NODE )
                        continue;
                    $this->attachedInterfaces[$ifNode->textContent] = $ifNode->textContent;
                }
            }
        }
    }

    /**
     * @return string[]
     */
    public function getAttachedInterfaces()
    {
        return $this->attachedInterfaces;
    }

    public function API_setName($newname)
    {
        if(! $this->isTmp() )
        {
            $c = findConnectorOrDie($this);

            $path = $this->getXPath();

            $c->sendRenameRequest($path, $newname);
        }
        else
        {
            mwarning('this is a temporary object, cannot be renamed from API');
        }

        $this->setName($newname);
    }

    public function &getXPath()
    {
        if( $this->isTmp() )
            derr('no xpath on temporary objects');

        $str = $this->owner->getXPath()."/entry[@name='".$this->name."']";

        return $str;
    }


    static protected $templatexml = '<entry name="**temporarynamechangeme**"><network><layer3></layer3></network></entry>';
	
}



