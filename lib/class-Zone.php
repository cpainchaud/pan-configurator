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
     * @param string $name
     * @param ZoneStore|null $owner
     */
 	public function Zone($name, $owner)
 	{
 		$this->owner = $owner;
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

        if( PH::$UseDomXML === TRUE )
            $this->xmlroot->getAttributeNode('name')->nodeValue = $newName;
        else
            $this->xmlroot['attributes']['name'] = $newName;

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
 	
	
}



