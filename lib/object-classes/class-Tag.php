<?php

/*
 * Copyright (c) 2014-2015 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
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
class Tag
{
	use ReferencableObject;
	use PathableName;
    use XmlConvertible;

    /** @var TagStore|null */
	public $owner = null;

    /** @var string|null */
    public $color;


    const NONE = 'none';
    const color1 = 'red';
    const color2 = 'green';
    const color3 = 'blue';
    const color4 = 'yellow';
    const color5 = 'copper';
    const color6 = 'orange';
    const color7 = 'purple';
    const color8 = 'gray';
    const color9 = 'light green';
    const color10 = 'cyan';
    const color11 = 'light gray';
    const color12 = 'blue gray';
    const color13 = 'lime';
    const color14 = 'black';
    const color15 = 'gold';
    const color16 = 'brown';
    const color17 = 'dark green';
    
    

    static public $TagColors = Array(
                                        self::NONE => 'none',
                                        self::color1 => 'color1',
                                        self::color2 => 'color2',
                                        self::color3 => 'color3',
                                        self::color4 => 'color4',
                                        self::color5 => 'color5',
                                        self::color6 => 'color6',
                                        self::color7 => 'color7',
                                        self::color8 => 'color8',
                                        self::color9 => 'color9',
                                        self::color10 => 'color10',
                                        self::color11 => 'color11',
                                        self::color12 => 'color12',
                                        self::color13 => 'color13',
                                        self::color14 => 'color14',
                                        self::color15 => 'color15',
                                        self::color16 => 'color16',
                                        self::color17 => 'color17'
                                    );

    /**
     * @param string $name
     * @param TagStore|null $owner
     * @param bool $fromXmlTemplate
     */
	public function __construct($name, $owner, $fromXmlTemplate=false )
	{
        $this->name = $name;


        if( $fromXmlTemplate )
        {
            $doc = new DOMDocument();
            if( $owner->owner->version < 60 )
                derr('tag stores were introduced in v6.0');
            else
                $doc->loadXML(self::$templatexml);

            $node = DH::findFirstElement('entry',$doc);

            $rootDoc = $owner->xmlroot->ownerDocument;

            $this->xmlroot = $rootDoc->importNode($node, true);
            $this->load_from_domxml($this->xmlroot);

            $this->setName($name);
        }

        $this->owner = $owner;

	}

    /**
     * @param string $newName
     * @return bool
     */
    public function setName($newName)
    {
        $ret = $this->setRefName($newName);

        if( $this->xmlroot === null )
            return $ret;

        $this->xmlroot->setAttribute('name', $newName);

        return $ret;
    }

    /**
     * @param string $newName
     */
    public function API_setName($newName)
    {
        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();
        $c->sendRenameRequest($xpath, $newName);
        $this->setName($newName);
    }


    /**
     * @param string $newColor
     * @param bool $rewriteXml
     * @return bool
     */
    public function setColor( $newColor, $rewriteXml = true )
    {
        if( !is_string($newColor) )
            derr('value can be text only');

        if( !isset(self::$TagColors[$newColor]) )
            derr("color '".$newColor."' not available");
        else
            $newColor = self::$TagColors[$newColor];

        if( $newColor == $this->color )
            return false;

        $this->color = $newColor;

        if( $rewriteXml)
        {
            $valueRoot = DH::findFirstElement('color', $this->xmlroot);
            if( $valueRoot == false )
            {
                $child = new DOMElement('color');

                $this->xmlroot->appendChild($child);
                $valueRoot = DH::findFirstElement('color', $this->xmlroot);
            }

            if( $newColor != 'none' )
                DH::setDomNodeText($valueRoot, $this->color);
            else
                $this->xmlroot->removeChild( $valueRoot);
        }

        return true;
    }

    /**
     * @param string $newColor
     * @return bool
     */
    public function API_setColor($newColor)
    {
        if( !$this->setColor($newColor) )
            return false;

        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        if( $newColor != 'none' )
        {
            $valueRoot = DH::findFirstElement('color', $this->xmlroot);
            $c->sendSetRequest($xpath,  DH::dom_to_xml($valueRoot,-1,false) );
            $this->setColor($newColor);
        }
        else
            $c->sendEditRequest($xpath,  DH::dom_to_xml($this->xmlroot,-1,false) );

        return true;
    }

    /**
     * @return array
     */
    public function availableColors( )
    {
        $ret = array_keys( self::$TagColors );

        return $ret;
    }

    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getTagStoreXPath()."/entry[@name='".$this->name."']";

        return $str;
    }
    

    public function isTmp()
    {
        if( $this->xmlroot === null )
            return true;
        return false;
    }


    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("tag name not found\n", $xml);

        if( strlen($this->name) < 1  )
            derr("Tag name '".$this->name."' is not valid.", $xml);

        //color
        $colorRoot = DH::findFirstElement('color', $xml);
        if( $colorRoot !== false )
            $this->color = $colorRoot->textContent;

        if( $this->color === FALSE || $this->color == '')
            $this->color = 'none';
            #derr("tag color not found\n", $colorRoot);

        if( strlen($this->color) < 1  )
            derr("Tag color '".$this->color."' is not valid.", $colorRoot);

    }

    /**
     * @return string
     */
    public function color()
    {
        $ret = $this->color;

        $lsearch = array_search( $this->color, self::$TagColors );
        if( $lsearch !== FALSE )
        {
            $ret = $lsearch;
        }

        return $ret;
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**"></entry>';
}

