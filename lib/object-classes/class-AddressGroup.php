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
	use XmlConvertible;

    private $isDynamic = false;

	/**
	 * @var DOMElement
	 */
	public $xmlroot;

    /**
     * @var AddressStore|null
     */
	public $owner=null;

    /**
     * @var Address[]|AddressGroup[]
     */
	private $members = Array();

	/**
	 * @var DOMElement
	 */
	private $membersRoot = null;

	/**
	 * @var TagStore
	 */
	public $tags;

	
	/**
	* Constructor for AddressGroup. There is little chance that you will ever need that. Look at AddressStore if you want to create an AddressGroup
	* @param string $name
	 * @param AddressStore|null $owner
     * @param bool $fromTemplateXml
	*
	*/
	function AddressGroup($name,$owner, $fromTemplateXml = false)
	{
        $this->owner = $owner;

		if( $fromTemplateXml )
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

			$this->setName($name);
		}
		
		$this->name = $name;

		$this->tags = new TagRuleContainer('tag', $this);
	}

	public function isDynamic()
	{
		return $this->isDynamic;
	}


	public function xml_convert_to_v6()
	{

		if( PH::$UseDomXML )
		{
			$newElement = $this->xmlroot->ownerDocument->createElement('static');
			$nodes = Array();

			foreach($this->xmlroot->childNodes as $node)
			{
				if( $node->nodeType != 1 )
					continue;

				$nodes[] = $node;
			}


			foreach($nodes as $node)
			{
				$newElement->appendChild($node);
			}


			$this->xmlroot->appendChild($newElement);

			return;
		}


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

		if( $this->owner->owner->version >= 60 )
		{
			$tagRoot = DH::findFirstElement('tag', $this->xmlroot);

			if( $tagRoot !== false )
				$this->tags->load_from_domxml($tagRoot);

			$this->membersRoot = DH::findFirstElement('static', $xml);

			if( $this->membersRoot === false )
			{
				$this->isDynamic = true;
			}
			else
			{
				foreach( $this->membersRoot->childNodes as $node)
				{
					if( $node->nodeType != 1 ) continue;

					$f = $this->owner->findOrCreate($node->textContent, $this, true);
					$this->members[] = $f;

				}
			}
		}
		else
		{
			foreach( $xml->childNodes as $node)
			{
				if( $node->nodeType != 1 ) continue;

				$f = $this->owner->findOrCreate($node->textContent, $this, true);
				$this->members[] = $f;

			}
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

		$this->xmlroot->setAttribute('name', $newname);
	}


	/**
	* @ignore
	* ** This is for internal use only **
	*
	*/
	public function referencedObjectRenamed($h)
	{

		if( in_array($h,$this->members, TRUE) )
		{
			$this->rewriteXML();
		}
	}
	
	/**
	* Add a member to this group, it must be passed as an object
	* @param Address|AddressGroup $newObject Object to be added
	* @param bool $rewriteXml
     * @return bool
	*/
	public function add($newObject, $rewriteXml = true)
	{
		if( $this->isDynamic )
			derr('cannot be used on Dynamic Address Groups');

		if( !is_object($newObject) )
			derr("Only objects can be passed to this function");

		if( ! in_array($newObject, $this->members, true) )
		{
			$this->members[] = $newObject;
			$newObject->addReference($this);
			if( $rewriteXml )
			{
				if( $this->owner->owner->version >= 60 )
				{
					$membersRoot = DH::findFirstElement('static', $this->xmlroot);
					if( $membersRoot === false )
					{
						derr('<static> not found');
					}

					$tmpElement = $membersRoot->appendChild($this->xmlroot->ownerDocument->createElement('member'));
					$tmpElement->nodeValue = $newObject->name();
				}
				else
				{
					$tmpElement = $this->xmlroot->appendChild($this->xmlroot->ownerDocument->createElement('member'));
					$tmpElement->nodeValue = $newObject->name();
				}
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
		if( $this->isDynamic )
			derr('cannot be used on Dynamic Address Groups');

		if( !is_object($old) )
			derr("Only objects can be passed to this function");

		$pos = array_search($old, $this->members, TRUE);
		
		if( $pos === FALSE )
			return false;
		else
		{
			unset($this->members[$pos]);
			$old->removeReference($this);
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

		if( $this->isDynamic )
			derr('cannot be called on Dynamic Address Group');

		foreach( $this->members as $a)
		{
			$a->removeReference($this);
		}
		$this->members = Array();


		if( $rewriteXml )
		{
			$this->rewriteXML();
		}

	}

    /**
     * @param Address|AddressGroup $old
     * @param Address|AddressGroup|null $new
     * @return bool
     */
	public function replaceReferencedObject($old, $new)
	{
		if( $old === null )
			derr("\$old cannot be null");
		
		$pos = array_search($old, $this->members, true);

		if( $pos !== FALSE )
		{
			if( !is_null($new)  )
			{
				$this->members[$pos] = $new;
				$new->addReference($this);
			}
			else
				unset($this->members[$pos]);

			$old->removeReference($this);


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

		if( $this->owner->owner->version >= 60 )
			DH::Hosts_to_xmlDom($this->membersRoot, $this->members, 'member', false);
		else
			DH::Hosts_to_xmlDom($this->xmlroot, $this->members, 'member', false);

	}
	
	/**
	* Counts how many members in this group
	* @return int
	*
	*/
	public function count()
	{
		if( $this->isDynamic )
			derr('unsupported with Dynamic Address Groups');
		return count($this->members);
	}

	/**
	 * returns the member list as an Array of objects (mix of Address, AddressGroups, Regions..)
	 * @return Address[]|AddressGroup[]
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

	/**
	 * Return true if other object is also a group and has same object name
	 *  ( value in not taken in account, only object name !! )
	 * @param AddressGroup $otherObject
	 * @return bool
	 */
	public function sameValue( AddressGroup $otherObject)
	{
		if( $this->isTmpAddr() && !$otherObject->isTmpAddr() )
			return false;

		if( $otherObject->isTmpAddr() && !$this->isTmpAddr() )
			return false;

		if( $otherObject->count() != $this->count() )
			return false;

		$diff = $this->getValueDiff($otherObject);

		if( count($diff['plus']) + count($diff['minus']) != 0 )
			return false;

		return true;
	}


	public function & getValueDiff( AddressGroup $otherObject)
	{
		$result = Array('minus' => Array(), 'plus' => Array() );

		$localObjects = $this->members;
		$otherObjects = $otherObject->members;


		usort($localObjects, '__CmpObjName');
		usort($otherObjects, '__CmpObjName');

		$diff = array_udiff($otherObjects, $localObjects, '__CmpObjName');

		if( count($diff) != 0 )
			foreach($diff as $d )
			{
				$result['minus'][] = $d;
			}

		$diff = array_udiff($localObjects, $otherObjects, '__CmpObjName');
		if( count($diff) != 0 )
			foreach($diff as $d )
			{
				$result['plus'][] = $d;
			}

		return $result;
	}


	public function displayValueDiff( AddressGroup $otherObject, $indent=0, $toString = false)
	{
		$retString = '';

		$indent = str_pad(' ', $indent);

		if( !$toString )
			print $indent."Diff for between ".$this->toString()." vs ".$otherObject->toString()."\n";
		else
			$retString .= $indent."Diff for between ".$this->toString()." vs ".$otherObject->toString()."\n";

		$diff = $this->getValueDiff($otherObject);

		if( count($diff['minus']) != 0 )
		{
			foreach($diff['minus'] as $d )
			{
				if( !$toString )
					print $indent." - {$d->name()}\n";
				else
					$retString .= $indent." - {$d->name()}\n";
			}
		}

		if( count($diff['plus']) != 0 )
			foreach($diff['plus'] as $d )
			{
				if( !$toString )
					print $indent." + {$d->name()}\n";
				else
					$retString .= $indent." + {$d->name()}\n";
			}

		if( $toString )
			return $retString;
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

	public function API_delete()
	{
		$connector = findConnectorOrDie($this);
		$xpath = $this->getXPath();

		$connector->sendDeleteRequest($xpath);
	}

	

	static protected $templatexml = '<entry name="**temporarynamechangeme**"></entry>';
    static protected $templatexml_v6 = '<entry name="**temporarynamechangeme**"><static></static></entry>';
    static protected $templatexmlroot = null;
}



