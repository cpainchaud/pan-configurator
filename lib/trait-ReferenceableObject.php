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
trait ReferencableObject
{

	protected $name;
	public $refrules = Array();
	protected $refcomphash = null;
	
	protected function setRefName($newName, $skip_name_unicity_check = false)
	{
		$oldName = $this->name;
		$this->name = $newName;
		
		$this->broadcastMyNameChange($oldName);
		
	}
	
	public function refInRule($ref)
	{
		refInRule($this,$ref);
		$this->refcomphash = null;
	}
	
	public function unrefInRule($ref)
	{
		unrefInRule($this,$ref);
		$this->refcomphash = null;
	}
	
	public function broadcastMyNameChange($oldname)
	{
		
		foreach( $this->refrules as $ref )
		{
			$ref->hostChanged($this,$oldname);
		}
		
		if( $this->owner )
		{
			$this->owner->hostChanged($this,$oldname);
		}
	}
	
	public function replaceMeGlobally($newobject)
	{
		foreach( $this->refrules as $o )
		{
			$o->replaceHostObject($this, $newobject);
		}
	}
	
	
	public function countReferences()
	{
		$c = count($this->refrules);
		
		return $c;
	}
	
	public function display_references()
	{
		print "Displaying referencers for ".$this->toString()."\n";
		foreach( $this->refrules as $o )
		{
			print $o->toString()."\n";
		}
	}
	
	public function findAssociatedSecurityRules()
	{
		return $this->findAssociatedRule_byType('SecurityRule');
	}
	
	public function findAssociatedRule_byType($type)
	{
		$cur = &$this->refrules;
		$c = count($cur);
		$k = array_keys($cur);
		
		$ret = Array();
		
		for($i=0; $i<$c; $i++)
		{
			if( isset($cur[$k[$i]]->owner) && !is_null($cur[$k[$i]]->owner) )
			{
				$class = get_class($cur[$k[$i]]->owner);
				//print $cur[$k[$i]]->owner->toString()."\n";
				if( $class == $type )
				{
					if( !in_array($cur[$k[$i]]->owner, $ret, TRUE) )
					{
						$ret[] = $cur[$k[$i]]->owner;
					}
				}
				
			}
		}
		
		return $ret;
	}
	
	
	public function generateRefHashComp($force=false)
	{
		if( !is_null($this->refcomphash) && !$force )
			return;
		
		$fasthashcomp = 'ReferenceableObject';
		
		$tmpa = $this->refrules;
		
		usort($tmpa, "__CmpObjMemID");
		
		foreach( $tmpa as $o )
		{
			$fasthashcomp .= '.*/'.spl_object_hash($o);
		}
		
		$this->refcomphash = md5($fasthashcomp,true);
		
	}
	
	public function getRefHashComp()
	{
		$this->generateRefHashComp();
		return $this->refcomphash;
	}

    public function getReferencers()
    {
        return $this->refrules;
    }
	
	
	public function name()
	{
		return $this->name;
	}
	
}
