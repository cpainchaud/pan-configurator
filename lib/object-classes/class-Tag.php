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
class Tag
{
	use ReferencableObject;
	use PathableName;
    use XmlConvertible;

    /** @var TagStore|null */
	public $owner = null;

    /** @var string|null */
    public $color;

    /** @var string|null */
    public $comments;

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
    //color18 not defined in PAN-OS
    const color19 = 'Maroon';

    const color20 = 'Red-Orange';
    const color21 = 'Yellow-Orange';
    const color22 = 'Forest Green';
    const color23 = 'Turquoise Blue';
    const color24 = 'Azure Blue';
    const color25 = 'Cerulean Blue';
    const color26 = 'Midnight Blue';
    const color27 = 'Medium Blue';
    const color28 = 'Cobalt Blue';
    const color29 = 'Violet Blue';

    const color30 = 'Blue Violet';
    const color31 = 'Medium Violet';
    const color32 = 'Medium Rose';
    const color33 = 'Lavender';
    const color34 = 'Orchid';
    const color35 = 'Thistle';
    const color36 = 'Peach';
    const color37 = 'Salmon';
    const color38 = 'Magenta';
    const color39 = 'Red Violet';

    const color40 = 'Mahogany';
    const color41 = 'Burnt Sienna';
    const color42 = 'Chestnut';
//

    
    

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
                                        self::color17 => 'color17',
                                        //color18 not defined in PAN-OS
                                        self::color19 => 'color19',

                                        self::color20 => 'color20',
                                        self::color21 => 'color21',
                                        self::color22 => 'color22',
                                        self::color23 => 'color23',
                                        self::color24 => 'color24',
                                        self::color25 => 'color25',
                                        self::color26 => 'color26',
                                        self::color27 => 'color27',
                                        self::color28 => 'color28',
                                        self::color29 => 'color29',

                                        self::color30 => 'color30',
                                        self::color31 => 'color31',
                                        self::color32 => 'color32',
                                        self::color33 => 'color33',
                                        self::color34 => 'color34',
                                        self::color35 => 'color35',
                                        self::color36 => 'color36',
                                        self::color37 => 'color37',
                                        self::color38 => 'color38',
                                        self::color39 => 'color39',

                                        self::color40 => 'color40',
                                        self::color41 => 'color41',
                                        self::color42 => 'color42'
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
            $commentsRoot = DH::findFirstElement('comments', $this->xmlroot);
            if( $valueRoot == false )
            {
                $child = new DOMElement('color');

                $this->xmlroot->appendChild($child);
                $valueRoot = DH::findFirstElement('color', $this->xmlroot);
            }



            if( $newColor != 'none' )
                DH::setDomNodeText($valueRoot, $this->color);
            else
            {
                $this->xmlroot->removeChild( $valueRoot);

                if( $commentsRoot === false )
                    $this->xmlroot->nodeValue = "";
            }

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
        {
            $c->sendEditRequest($xpath,  DH::dom_to_xml($this->xmlroot,-1,false) );
        }


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


        $colorRoot = DH::findFirstElement('color', $xml);
        if( $colorRoot !== false )
            $this->color = $colorRoot->textContent;

        if( $this->color === FALSE || $this->color == '')
            $this->color = 'none';

        if( strlen($this->color) < 1  )
            derr("Tag color '".$this->color."' is not valid.", $colorRoot);


        $commentsRoot = DH::findFirstElement('comments', $xml);
        if( $commentsRoot !== false )
            $this->comments = $commentsRoot->textContent;

        if( $this->comments === FALSE || $this->comments == '')
            $this->comments = '';
    }

    /**
     * @return string
     */
    public function getColor()
    {
        $ret = $this->color;

        $lsearch = array_search( $this->color, self::$TagColors );
        if( $lsearch !== FALSE )
        {
            $ret = $lsearch;
        }

        return $ret;
    }

    /**
     * @return string
     */
    public function getComments()
    {
        $ret = $this->comments;

        return $ret;
    }

    /**
     * * @param string $newComment
     * * @param bool $rewriteXml
     * @return bool
     */
    public function addComments( $newComment, $rewriteXml = true )
    {
        $oldComment = $this->comments;
        $newComment = $oldComment.$newComment;


        if( $this->xmlroot === null )
            return false;

        if( $rewriteXml )
        {
            $commentsRoot = DH::findFirstElement('comments', $this->xmlroot);
            if( $commentsRoot === false)
            {
                $child = new DOMElement('comments');
                $this->xmlroot->appendChild($child);
                $commentsRoot = DH::findFirstElement('comments', $this->xmlroot);
            }

            DH::setDomNodeText($commentsRoot, $newComment );
        }


        return true;
    }

    /**
     * @param string $newComment
     * @return bool
     */
    public function API_addComments($newComment)
    {
        if( !$this->addComments($newComment) )
            return false;

        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        $commentsRoot = DH::findFirstElement('comments', $this->xmlroot);
        $c->sendEditRequest($xpath."/comments",  DH::dom_to_xml($commentsRoot,-1,false) );
        $this->addComments($newComment);

        return true;
    }

    /**
     * @return bool
     */
    public function deleteComments( )
    {
        if( $this->xmlroot === null )
            return false;

        $commentsRoot = DH::findFirstElement('comments', $this->xmlroot);
        $valueRoot = DH::findFirstElement('color', $this->xmlroot);
        if( $commentsRoot !== false )
            $this->xmlroot->removeChild( $commentsRoot);

        if( $valueRoot === false )
            $this->xmlroot->nodeValue = "";

        return true;
    }

    /**
     * @return bool
     */
    public function API_deleteComments( )
    {
        if( !$this->deleteComments() )
            return false;

        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        $c->sendEditRequest($xpath,  DH::dom_to_xml($this->xmlroot,-1,false) );

        return true;
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

    public function isTag()
    {
        return true;
    }

    /**
     * @param $otherObject Tag
     * @return bool
     */
    public function equals( $otherObject )
    {
        if( ! $otherObject->isTag() )
            return false;

        if( $otherObject->name != $this->name )
            return false;

        return $this->sameValue( $otherObject);
    }

    public function sameValue( Tag $otherObject)
    {
        if( $this->isTmp() && !$otherObject->isTmp() )
            return false;

        if( $otherObject->isTmp() && !$this->isTmp() )
            return false;

        if( $otherObject->color !== $this->color )
            return false;

        return true;
    }
}

