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


class ServiceGroup
{
	use PathableName;
	use XmlConvertible;
    use ServiceCommon;

    /** @var Service[]|ServiceGroup[] */
	public $members = Array();

	/** @var null|ServiceStore */
	public $owner = null;

    /** @var TagRuleContainer */
    public $tags;

    
	public function __construct($name,$owner=null, $fromTemplateXml = false)
	{
		$this->owner = $owner;

        if( $fromTemplateXml )
        {
            $doc = new DOMDocument();
            $doc->loadXML(self::$templatexml);

            $node = DH::findFirstElement('entry',$doc);

            $rootDoc = $this->owner->serviceGroupRoot->ownerDocument;

            $this->xmlroot = $rootDoc->importNode($node, true);
            $this->load_from_domxml($this->xmlroot);

            $this->name = $name;
            $this->xmlroot->setAttribute('name', $name);
        }

        $this->name = $name;

        $this->tags = new TagRuleContainer($this);
	}


	/**
	 * returns number of members in this group
	 * @return int
	 */
	public function count()
	{
		return count($this->members);
	}


	public function load_from_domxml($xml)
	{
		$this->xmlroot = $xml;
		
		$this->name = DH::findAttribute('name', $xml);
		if( $this->name === FALSE )
			derr("name not found\n");

		if( $this->owner->owner->version >= 60 )
		{
			$membersRoot = DH::findFirstElement('members', $this->xmlroot);

			if( $membersRoot === false )
			{
				derr('unsupported non v6 syntax type ServiceGroup', $this->xmlroot);
			}

			foreach( $membersRoot->childNodes as $node)
			{
				if( $node->nodeType != 1 ) continue;

                $memberName = $node->textContent;

                if( strlen($memberName) < 1 )
                    derr('found a member with empty name !', $node);

				$f = $this->owner->findOrCreate($memberName, $this, true);

                $alreadyInGroup = false;
                foreach( $this->members as $member )
                    if( $member === $f )
                    {
                        mwarning("service '{$memberName}' is already part of group '{$this->name}', you should review your config file");
                        $alreadyInGroup = true;
                        break;
                    }

                if( !$alreadyInGroup )
				    $this->members[] = $f;
			}

		}
		else
		{
			foreach( $xml->childNodes as $node)
			{
				if( $node->nodeType != 1 ) continue;

                $memberName = $node->textContent;

                if( strlen($memberName) < 1 )
                    derr('found a member with empty name !', $node);

				$f = $this->owner->findOrCreate($memberName, $this, true);

                $alreadyInGroup = false;
                foreach( $this->members as $member )
                    if( $member === $f )
                    {
                        mwarning("duplicated member named '{$memberName}' detected in service group '{$this->name}', you should review your XML config file", $this->xmlroot);
                        $alreadyInGroup = true;
                        break;
                    }

                if( !$alreadyInGroup )
                    $this->members[] = $f;

				$this->members[] = $f;

			}
		}

        if( $this->owner->owner->version >= 60 )
        {
            $tagRoot = DH::findFirstElement('tag', $xml);
            if( $tagRoot !== false )
                $this->tags->load_from_domxml($tagRoot);
        }
	
	}

    /**
     * @param $newName string
     */
	public function setName($newName)
	{
		$this->setRefName($newName);
		$this->xmlroot->setAttribute('name', $newName);
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
	 * @param Service|ServiceGroup $newObject
	 * @param bool $rewriteXml
	 * @return bool
	 */
	public function addMember($newObject, $rewriteXml = true)
	{
		
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
					$membersRoot = DH::findFirstElement('members', $this->xmlroot);
					if( $membersRoot === false )
						derr('<members> not found');

                    DH::createElement($membersRoot, 'member', $newObject->name());
				}
				else
				{
                    DH::createElement($this->xmlroot, 'member', $newObject->name());
				}
			}
			
			return true;
		}
		
		return false;
	}

    /**
     * @param Service|ServiceGroup objectToRemove
     * @return bool
     */
    public function API_removeMember( $objectToRemove)
    {
        $ret = $this->removeMember($objectToRemove);

        if( $ret )
        {
            $con = findConnector($this);
            $xpath = $this->getXPath();

            if( $this->owner->owner->version >= 60 )
                $xpath .= '/members';

            $con->sendDeleteRequest($xpath."/member[text()='{$objectToRemove->name()}']");

            return $ret;
        }

        return $ret;
    }


    /**
     * Add a member to this group, it must be passed as an object
     * @param Service|ServiceGroup $newObject Object to be added
     * @return bool
     */
    public function API_addMember($newObject)
    {
        $ret = $this->addMember($newObject);

        if( $ret )
        {
            $con = findConnector($this);
            $xpath = $this->getXPath();

            if( $this->owner->owner->version >= 60 )
                $xpath .= '/members';

            $con->sendSetRequest($xpath, "<member>{$newObject->name()}</member>");
        }

        return $ret;
    }

	/**
	 * @param Service|ServiceGroup $old
	 * @param bool $rewritexml
	 * @return bool
	 */
	public function removeMember( $old , $rewritexml = true)
	{
		if( !is_object($old) )
			derr("Only objects can be passed to this function");
		
		
		$found = false;
		$pos = array_search($old, $this->members, TRUE);
		
		if( $pos === FALSE )
			return false;
		else
		{
			$found = true;
			unset($this->members[$pos]);
			$old->removeReference($this);
			if($rewritexml)
				$this->rewriteXML();
		}
		
		
		return $found;
	}

	public function &getXPath()
	{
		$str = $this->owner->getServiceGroupStoreXPath()."/entry[@name='".$this->name."']";

		return $str;
	}

    /**
     * @param Service|ServiceGroup $old
     * @param Service|ServiceGroup $new
     * @return bool
     * @throws Exception
     */
	public function replaceReferencedObject($old, $new)
	{
		if( $old === null )
			derr("\$old cannot be null");

		if( in_array($old, $this->members, true) )
		{
			if( $new !== null )
			{
				$this->addMember($new, false);
				if( $old->name() == $new->name() )
					$this->removeMember($old, false);
				else
					$this->removeMember($old);
			}
			else
				$this->removeMember($old);
			
			return true;
		}
				
		return false;
	}

    public function API_replaceReferencedObject($old, $new)
    {
        $ret = $this->replaceReferencedObject($old, $new);

        if($ret)
        {
            $this->API_sync();
        }

        return $ret;
    }

	
	public function rewriteXML()
	{
        if( $this->owner->owner->version >= 60 )
        {
            $membersRoot = DH::findFirstElement('members', $this->xmlroot);
            if( $membersRoot === false )
            {
                derr('<members> not found');
            }
            DH::Hosts_to_xmlDom($membersRoot, $this->members, 'member', false);
        }
        else
            DH::Hosts_to_xmlDom($this->xmlroot, $this->members, 'member', false);
	}
	
	/**
	* @param Service|ServiceGroup $h
	*
	*/
	public function referencedObjectRenamed($h)
	{
		//derr("****  SG referencedObjectRenamed was called  ****\n");
		if( in_array($h, $this->members, true) )
			$this->rewriteXML();
	}

	public function isGroup()
	{
		return true;
	}


	/**
	 * @param Service|ServiceGroup $otherObject
	 * @return bool true if objects have same same and values
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
	 * @param ServiceGroup $otherObject
	 * @return bool true if both objects contain same objects names
	 */
	public function sameValue( ServiceGroup $otherObject)
	{
		if( $this->isTmpSrv() && !$otherObject->isTmpSrv() )
			return false;

		if( $otherObject->isTmpSrv() && !$this->isTmpSrv() )
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

		$diff = array_diff($lO, $oO);

		if( count($diff) != 0 )
			return false;

		return true;
	}

    public function &getValueDiff( ServiceGroup $otherObject)
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


    /**
     * @param ServiceGroup $otherObject
     * @param int $indent
     * @param bool|false $toString
     * @return string|void
     */
	public function displayValueDiff( ServiceGroup $otherObject, $indent=0, $toString = false)
	{
		$retString = '';

		$indent = str_pad(' ', $indent);

		if( !$toString )
			print $indent."Diff between ".$this->_PANC_shortName()." vs ".$otherObject->_PANC_shortName()."\n";
		else
			$retString .= $indent."Diff for between ".$this->_PANC_shortName()." vs ".$otherObject->_PANC_shortName()."\n";

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
		{
			foreach($diff as $d )
			{
				if( !$toString )
					print $indent." - $d\n";
				else
					$retString .= $indent." - $d\n";
			}
		}

		$diff = array_diff($lO, $oO);
		if( count($diff) != 0 )
			foreach($diff as $d )
			{
				if( !$toString )
					print $indent." + $d\n";
				else
					$retString .= $indent." + $d\n";
			}

		if( $toString )
			return $retString;
	}


    /**
     * @return ServiceDstPortMapping
     */
    public function dstPortMapping()
    {
        $mapping = new ServiceDstPortMapping();

        foreach( $this->members as $member)
        {
            if( $member->isTmpSrv() )
                $mapping->unresolved[$member->name()] = $member;
            $localMapping = $member->dstPortMapping();
            $mapping->mergeWithMapping($localMapping);
        }

        return $mapping;
    }


	public function xml_convert_to_v6()
	{
        $newElement = $this->xmlroot->ownerDocument->createElement('members');
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


	/**
     * @param bool $keepGroupsInList
	* @return Service[]|ServiceGroup[] list of all member objects, if some of them are groups, they are exploded and their members inserted
	*/
	public function &expand($keepGroupsInList=false)
	{
		$ret = Array();

		foreach( $this->members as  $object )
		{
			if( $object->isGroup() )
			{
                if( $this->name() == $object->name() )
                {
                    mwarning( "servicegroup with name: ".$this->name()." is added as subgroup to itself, you should review your XML config file" );
                    continue;
                }


				$ret = array_merge( $ret, $object->expand() );
                if( $keepGroupsInList )
                    $ret[] = $object;
			}
			else
				$ret[] = $object;
		}

		$ret = array_unique_no_cast($ret);

		return $ret;
	}

    /**
     * @return Service[]|ServiceGroup[]
     */
	public function members()
	{
		return $this->members;
	}


	/**
	 * @param Service|ServiceGroup $object
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

    /**
     * @param string $objectName
     * @return bool
     */
    public function hasNamedObjectRecursive($objectName)
    {
        foreach( $this->members as $o )
        {
            if( $o->name() === $objectName )
                return true;
            if( $o->isGroup() )
                if( $o->hasNamedObjectRecursive($objectName) ) return true;
        }

        return false;
    }


    public function removeAll($rewriteXml = true)
    {
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

    static protected $templatexml = '<entry name="**temporarynamechangeme**"><members></members></entry>';
    static protected $templatexmlroot = null;
}


