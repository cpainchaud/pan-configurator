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

class AddressGroup
{
	use PathableName;
	use ReferencableObject;

    private $isDynamic = false;
	
	public $xmlroot;

    /**
     * @var AddressStore|null
     */
	public $owner=null;

    /**
     * @var Address[]|AddressGroup[]
     */
	private $members = Array();


    public function isDynamic()
    {
        return $this->isDynamic;
    }
	
	/**
	* Constructor for AddressGroup. There is little chance that you will ever need that. Look at AddressStore if you want to create an AddressGroup
	* @param string $name
     * @param PANConf|PanoramaConf|VirtualSystem|DeviceGroup $owner
     * @param bool $fromTemplateXml
	* @param AddressStore|null $owner
	*
	*/
	function AddressGroup($name,$owner, $fromTemplateXml = false)
	{
        $this->owner = $owner;

		if( $fromTemplateXml )
		{
            if( !PH::$UseDomXML )
            {
                $xmlobj = new XmlArray();
                if( $this->owner->owner->version < 60 )
                    $xmlArray = $xmlobj->load_string(self::$templatexml);
                else
                    $xmlArray = $xmlobj->load_string(self::$templatexml_v6);
                $this->load_from_xml($xmlArray);
            }
            else
            {
                $doc = new DOMDocument();
                if( $this->owner->owner->version < 60 )
                    $doc->loadXML(self::$templatexml);
                else
                    $doc->loadXML(self::$templatexml_v6);

                $node = DH::findFirstElement('entry',$doc);

                $rootDoc = $this->owner->addrgroot->ownerDocument;

                $this->xmlroot = $rootDoc->importNode($node, true);
                $this->load_from_domxml($this->xmlroot);

            }
			$this->setName($name);
		}
		
		$this->name = $name;

		
	}
	
	/**
	* @ignore
	*
	*/
	public function load_from_xml(&$xml)
	{
		
		$this->xmlroot = &$xml;
		
		$this->name = $xml['attributes']['name'];
		if( is_null($this->name) )
			derr("address group name not found\n");
		
		
		
		if( !isset($this->xmlroot['children']) )
			$this->xmlroot['children'] = Array();
		
		$a = &$this->xmlroot['children'];

        if( $this->owner->version >= 60 )
        {
            $this->membersRoot = &searchForName('name', 'static', $this->xmlroot['children']);

            if( $this->membersRoot === null )
            {
                $this->membersRoot = &searchForName('name', 'static', $this->xmlroot['children']);
                $this->isDynamic = true;
                return;
            }

            if( $this->membersRoot === null )
                derr('unsupported group that is not static or dynamic');

            $a = &$this->membersRoot['children'];
        }
		
		foreach( $a as &$r )
		{
			$f = $this->owner->findOrCreate($r['content'], $this, true);
			$this->members[] = $f;
		}
		
	}

	public function xml_convert_to_v6()
	{
		$ar = Array('name' => 'static'  );

		$ar['children'] = &$this->xmlroot['children'];

		$tmp = Array();

		$this->xmlroot['children'] = &$tmp;
		$this->xmlroot['children'][] = &$ar;

	}

	/**
	* @ignore
	*
	*/
	public function load_from_domxml($xml)
	{
		
		$this->xmlroot = $xml;
		
		$this->name = DH::findAttribute('name', $xml);
		if( $this->name === FALSE )
			derr("name not found\n");
		
		
		foreach( $xml->childNodes as $node)
		{
			if( $node->nodeType != 1 ) continue;

			$f = $this->owner->findOrCreate($node->textContent, $this, true);
			$this->members[] = $f;
			
		}
		
	}

    /**
     * @return string
     */
	public function name()
	{
		return $this->name;
	}	
	
	public function setName($newname)
	{
		$this->setRefName($newname);

		if( PH::$UseDomXML === TRUE )
			$this->xmlroot->setAttribute('name', $newname);
		else
			$this->xmlroot['attributes']['name'] = $newname;
	}
	
	

	/**
	* @ignore
	* ** This is for internal use only **
	*
	*/
	public function hostChanged($h)
	{

		if( in_array($h,$this->members, TRUE) )
		{
			$this->rewriteXML();
		}
	}
	
	/**
	* Add a member to this group, it must be passed as an object
	* @param Address|AddressGroup $newO Object to be added
	* @param bool $rewriteXml
     * @return bool
	*/
	public function add($newO, $rewriteXml = true)
	{
		
		if( !is_object($newO) )
			derr("Only objects can be passed to this function");
		
		if( ! in_array($newO, $this->members, true) )
		{
			$this->members[] = $newO;
			$newO->refInRule($this);
			if( $rewriteXml )
			{
				$this->rewriteXML();
			}
			
			return true;
		}
		
		return false;
	}

    /**
     * Removes a member from this group
     * @param Address|AddressGroup $old Object to be removed
     * @param bool $rewriteXml
     * @return bool
     */
	public function remove( $old, $rewriteXml = true )
	{
		if( !is_object($old) )
			derr("Only objects can be passed to this function");

		$pos = array_search($old, $this->members, TRUE);
		
		if( $pos === FALSE )
			return false;
		else
		{
			unset($this->members[$pos]);
			$old->unRefInRule($this);
			if($rewriteXml)
				$this->rewriteXML();
		}
		
		return true;
	}

	/**
	* Clear this Group from all its members
	*
	*
	*/
	public function removeAll($rewriteXml = true)
	{

		foreach( $this->members as $a)
		{
			$a->unRefInRule($this);
		}
		$this->members = Array();


		if( $rewriteXml )
		{
			if( PH::$UseDomXML === TRUE)
				DH::clearNodeChilds($this->xmlroot);
			else	
				$this->xmlroot['children'] = Array();
		}

	}

    /**
     * @param Address|AddressGroup $old
     * @param Address|AddressGroup|null $new
     * @return bool
     */
	public function replaceHostObject($old, $new)
	{
		if( $old === null )
			derr("\$old cannot be null");
		
		$pos = array_search($old, $this->members, true);

		if( $pos !== FALSE )
		{
			if( !is_null($new)  )
			{
				$this->members[$pos] = $new;
				$new->refInRule($this);
			}
			else
				unset($this->members[$pos]);

			$old->unRefInRule($this);


			if( $new !== null && $new->name() != $old->name() )
				$this->rewriteXML();
			
			return true;
		}
		
		return false;		

	}
	
	/**
	* Rewrite XML for this object, useful after a batch editing to save computing time
	*
	*/
	public function rewriteXML()
	{
        if( $this->isDynamic() )
            derr('unsupported');

		if( PH::$UseDomXML === TRUE)
		{
			DH::Hosts_to_xmlDom($this->xmlroot, $this->members, 'member', false);
		}
		else
        {
            if( $this->owner->version >= 60 )
                Hosts_to_xmlA($this->membersRoot['children'], $this->members, 'member', false);
            else
                Hosts_to_xmlA($this->xmlroot['children'], $this->members, 'member', false);
        }
	}
	
	/**
	* Counts how many members in this group
	* @return int
	*
	*/
	public function count()
	{
		return count($this->members);
	}
	
	/**
	* returns the member list as an Array of objects (mix of Address, AddressGroups, Regions..)
	*
	*/
	public function members()
	{
		return $this->members;
	}

	public function API_setName($newName)
	{
		$c = findConnectorOrDie($this);
		$path = $this->getXPath();

		$url = "type=config&action=rename&xpath=$path&newname=$newName";

		$c->sendRequest($url);

		$this->setName($newName);
	}

	/**
	* @return string
	*/
	public function & getXPath()
	{
		$str = $this->owner->getAddressGroupStoreXPath()."/entry[@name='".$this->name."']";

		return $str;
	}

	public function isGroup()
	{
		return true;
	}

	public function isAddress()
	{
		return false;
	}

	public function isTmpAddr()
	{
		return false;
	}

    /**
     * @param Address|AddressGroup $otherObject
     * @return bool
     */
	public function equals( $otherObject )
	{
		if( ! $otherObject->isGroup() )
			return false;

		if( $otherObject->name != $this->name )
			return false;


		return $this->sameValue( $otherObject);
	}

	public function sameValue( AddressGroup $otherObject)
	{
		if( $this->isTmpAddr() && !$otherObject->isTmpAddr() )
			return false;

		if( $otherObject->isTmpAddr() && !$this->isTmpAddr() )
			return false;

		if( $otherObject->count() != $this->count() )
			return false;

		$lO = Array();
		$oO = Array();

		foreach($this->members as $a)
		{
			$lO[] = $a->name();
		}
		sort($lO);

		foreach($otherObject->members as $a)
		{
			$oO[] = $a->name();
		}
		sort($oO);

		$diff = array_diff($oO, $lO);

		if( count($diff) != 0 )
			return false;

		return true;
	}

	/**
	* @return Array list of all member objects, if some of them are groups, they are exploded and their members inserted
	*/
	public function & expand()
	{
		$ret = Array();

		foreach( $this->members as  $object )
		{
			if( $object->isGroup() )
			{
				$ret = array_merge( $ret, $object->expand() );
			}
			else
				$ret[] = $object;
		}

		$ret = array_unique_no_cast($ret);

		return $ret;
	}

	/**
	 * @param Address|AddressGroup $object
	 * @return bool
	 */
    public function hasObjectRecursive($object)
    {
        if( $object === null )
            derr('cannot work with null objects');


        foreach( $this->members as $o )
        {
            if( $o === $object )
                return true;
            if( $o->isGroup() )
                if( $o->hasObjectRecursive($object) ) return true;
        }

        return false;
    }

	

	static protected $templatexml = '<entry name="**temporarynamechangeme**"></entry>';
    static protected $templatexml_v6 = '<entry name="**temporarynamechangeme**"><static></static></entry>';
    static protected $templatexmlroot = null;
}



