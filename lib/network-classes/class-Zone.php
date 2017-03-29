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
class Zone
{

	use ReferencableObject;
	use PathableName;
    use XmlConvertible;

    /** @var null|ZoneStore */
    public $owner = null;
	
	private $isTmp = true;

    public $externalVsys = Array();

    public $_type = 'tmp';


    /** @var InterfaceContainer */
    public $attachedInterfaces;


    const TypeTmp = 0;
    const TypeLayer3 = 1;
    const TypeExternal = 2;

    static private $ZoneTypes = Array(self::TypeTmp => 'tmp',
        self::TypeLayer3 => 'layer3',
        self::TypeExternal => 'external',
         );


    /**
     * @param string $name
     * @param ZoneStore $owner
     */
 	public function __construct($name, $owner, $fromXmlTemplate = false)
 	{
        if( !is_string($name) )
            derr('$name must be a string');

        $this->owner = $owner;

        if( $this->owner->owner->isVirtualSystem() )
        {
            $this->attachedInterfaces = new InterfaceContainer($this, $this->owner->owner->owner->network);
        }
        else
            $this->attachedInterfaces = new InterfaceContainer($this, null);


        if( $fromXmlTemplate )
        {
            $doc = new DOMDocument();
            $doc->loadXML(self::$templatexml);

            $node = DH::findFirstElementOrDie('entry',$doc);

            $rootDoc = $this->owner->xmlroot->ownerDocument;
            $this->xmlroot = $rootDoc->importNode($node, true);
            $this->load_from_domxml($this->xmlroot);

            $this->owner = null;
            $this->setName($name);
            $this->owner = $owner;
        }

		$this->name = $name;
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

    public function isTmp()
    {
        return $this->isTmp;
    }

    public function type()
    {
        return $this->_type;
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

        $networkNode = DH::findFirstElement('network', $xml);

        if( $networkNode === false )
            return;

        foreach( $networkNode->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            if( $node->tagName == 'layer3')
            {
                $this->_type = 'layer3';

                $this->attachedInterfaces->load_from_domxml($node);
            }
            else if( $node->tagName == 'external')
            {
                $this->_type = 'external';
                foreach($node->childNodes as $memberNode)
                {
                    if( $memberNode->nodeType != XML_ELEMENT_NODE )
                        continue;
                    $this->externalVsys[$memberNode->textContent] = $memberNode->textContent;
                }

                $this->attachedInterfaces->load_from_domxml($node);
            }
        }
    }

    /**
     * @param $objectToAdd Zone
     * @param $displayOutput bool
     * @param $skipIfConflict bool
     * @param $outputPadding string|int
     */
    public function addObjectWhereIamUsed($objectToAdd, $displayOutput = false, $outputPadding = '', $skipIfConflict = false)
    {
        foreach( $this->refrules as $ref )
        {
            $refClass = get_class($ref);
            if( $refClass == 'ZoneRuleContainer' )
            {
                /** @var ZoneRuleContainer $ref */
                $ownerClass = get_class($ref->owner);

                if( $ownerClass == 'SecurityRule' )
                {
                    $ref->addZone($objectToAdd);
                }
                else
                {
                    derr("unsupported owner class '{$ownerClass}'");
                }
            }
            else
                derr("unsupported class '{$refClass}");
        }
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



