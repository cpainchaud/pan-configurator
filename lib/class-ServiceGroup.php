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
class ServiceGroup
{
	use PathableName;
	use ReferencableObject;
	use XmlConvertible;

    /**
     * @var Service|ServiceGroup[]
     */
	public $services = Array();
	
	public $xmlroot = null; 
	 
	public $owner = null;

	
	
	public function ServiceGroup($name,$owner=null)
	{
		$this->owner = $owner;
		$this->name = $name;
	}
	 
	public function load_from_xml(&$xml)
	{
		$this->xmlroot = &$xml;
		$this->name = $xml['attributes']['name'];
		if( is_null($this->name) )
			derr("service group name not found\n");

        if( $this->owner->version >= 60 )
        {
            if( !isset($this->xmlroot['children']) )
                $this->xmlroot['children'] = Array();

            $this->membersRoot = &searchForName('name', 'static', $this->xmlroot['children']);

            if( $this->membersRoot === null )
            {
                $this->membersRoot = Array( 'name' => 'static' , 'children' => Array() );
                $this->xmlroot['children'][] = &$this->membersRoot;
            }
            if( !isset($membersRoot['children']) )
            {
                $this->membersRoot['children'] = Array();
            }

            $a = &$this->membersRoot['children'];
        }
		else
		    $a = &$this->xmlroot['children'];

		
		foreach( $a as &$r )
		{
			//print "found member '".$a[$k[$i]]['content']."' in ServiceGroup '".$this->name."'\n";
			//print $this->owner->toString()."\n";
            //print_r($r);
			$f = $this->owner->findOrCreate($r['content'], $this);
			if( !$f )
				derr($this->toString().' '.__FUNCTION__."() Error: unknown object named '".$r['content']."\n");
			
			$this->services[] = $f;
		}
	
	}


	/**
	 * returns number of members in this group
	 * @return int
	 */
	public function count()
	{
		return count($this->services);
	}


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
			$this->services[] = $f;
			
		}
	
	}
	
	
	
 
 
	public function setName($newname)
	{
		$this->xmlroot['attributes']['name'] = $newname;
		$this->setRefName($newname);
		
	}
	
	public function add($newO, $rewritexml = true)
	{
		
		if( !is_object($newO) )
			derr("Only objects can be passed to this function");
		
		if( ! in_array($newO, $this->services, true) )
		{
			$this->services[] = $newO;
			$newO->refInRule($this);
			if( $rewritexml )
			{
				$this->rewriteXML();
			}
			
			return true;
		}
		
		return false;
	}
	
	/**
	* Removes a member from this group
	*
	*/
	public function remove( $old , $rewritexml = true)
	{
		if( !is_object($old) )
			derr("Only objects can be passed to this function");
		
		
		$found = false;
		$pos = array_search($old, $this->services, TRUE);
		
		if( $pos === FALSE )
			return false;
		else
		{
			$found = true;
			unset($this->services[$pos]);
			$old->unRefInRule($this);
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
	
	public function replaceHostObject($old, $new)
	{
		if( is_null($old) )
			derr("\$old cannot be null");
		

		if( in_array($old, $this->services, true) !== FALSE )
		{
			if( !is_null($new) )
				$this->add($new,false);
			$this->remove($old);
			
			return true;
		}
				
		return false;
	}
	
	
	public function rewriteXML()
	{
		if( PH::$UseDomXML === TRUE )
			DH::Hosts_to_xmlDom($this->xmlroot, $this->services, 'member', false);
		else
        {
            if( $this->owner->version >= 60 )
                Hosts_to_xmlA($this->membersRoot['children'], $this->services, 'member', false);
            else
                Hosts_to_xmlA($this->xmlroot['children'], $this->services, 'member', false);
        }
	}
	
	/**
	*
	*
	*/
	public function hostChanged($h)
	{
		//derr("****  SG hostChanged was called  ****\n");
		if( in_array($h, $this->services) )
			$this->rewriteXML();
	}
	
	public function name()
	{
		return $this->name;
	}

	public function isService()
	{
		return false;
	}

	public function isGroup()
	{
		return true;
	}

	public function isTmpSrv()
	{
		return false;
	}


	/**
	 * @param $otherObject
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

		foreach($this->services as $a)
		{
			$lO[] = $a->name();
		}
		sort($lO);

		foreach($otherObject->services as $a)
		{
			$oO[] = $a->name();
		}
		sort($oO);

		$diff = array_diff($oO, $lO);

		if( count($diff) != 0 )
			return false;

		return true;
	}


	public function xml_convert_to_v6()
	{
		$ar = Array('name' => 'members'  );

		$ar['children'] = &$this->xmlroot['children'];

		$tmp = Array();

		$this->xmlroot['children'] = &$tmp;
		$this->xmlroot['children'][] = &$ar;

	}


	/**
	* @return Array list of all member objects, if some of them are groups, they are exploded and their members inserted
	*/
	public function & expand()
	{
		$ret = Array();

		foreach( $this->addresses as  $object )
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
	
	
}


