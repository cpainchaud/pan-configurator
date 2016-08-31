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
trait ReferencableObject
{

	protected $name;
	public $refrules = Array();
	protected $refcomphash = null;

    /**
     * @param string $newName
     * @param bool $skip_name_unicity_check
     * @throws Exception
     * @return bool
     */
	protected function setRefName($newName, $skip_name_unicity_check = false)
	{
        if( !is_string($newName) )
            derr('$newName must be a string');

        if( $this->name == $newName )
            return false;

		$oldName = $this->name;
		$this->name = $newName;
		
		$this->broadcastMyNameChange($oldName);

        return true;
	}
	
	public function addReference($ref)
	{
		if( $ref === null )
			return;

		$serial = spl_object_hash($ref);

		if( isset($this->refrules[$serial]) )
			return;

		$this->refrules[$serial] = $ref;
		$this->refcomphash = null;
	}
	
	public function removeReference($ref)
	{
		if( $ref === null )
			return;

		$serial = spl_object_hash($ref);

		if( isset($this->refrules[$serial]) )
		{
			unset($this->refrules[$serial]);
			$this->refcomphash = null;
			return;
		}

		mwarning('tried to unreference an object that is not referenced:'.$this->toString().'  against  '.$ref->toString());
	}
	
	public function broadcastMyNameChange($oldname)
	{
		
		foreach( $this->refrules as $ref )
		{
			$ref->referencedObjectRenamed($this,$oldname);
		}
		
		if( $this->owner !== null )
		{
			$this->owner->referencedObjectRenamed($this,$oldname);
		}
	}
	
	public function replaceMeGlobally($newobject)
	{
		foreach( $this->refrules as $o )
		{
			$o->replaceReferencedObject($this, $newobject);
		}
	}

    /**
     * @param $objectToAdd Service|ServiceGroup
     * @param $displayOutput bool
     * @param $skipIfConflict bool
     * @param $outputPadding string|int
     */
    public function addObjectWhereIamUsed($objectToAdd, $displayOutput = false, $outputPadding = '', $skipIfConflict = false)
    {
        derr('not implemented yet');
    }

    /**
     * @param $objectToAdd Service|ServiceGroup
     * @param $displayOutput bool
     * @param $skipIfConflict bool
     * @param $outputPadding string|int
     */
    public function API_addObjectWhereIamUsed($objectToAdd, $displayOutput = false, $outputPadding = '', $skipIfConflict = false)
    {
        derr('not implemented yet');
    }
	
	
	public function countReferences()
	{
		return count($this->refrules);
	}

	
	public function display_references($indent=0)
	{
		$strpad = str_pad('',$indent);
		print $strpad."* Displaying referencers for ".$this->toString()."\n";
		foreach( $this->refrules as $o )
		{
			print $strpad.'  - '.$o->toString()."\n";
		}
	}

	/**
	 * @return SecurityRule[]
	 */
	public function findAssociatedSecurityRules()
	{
		return $this->findAssociatedRule_byType('SecurityRule');
	}

	/**
	 * @param string $type
	 * @return Rule[]
	 */
	public function findAssociatedRule_byType($type)
	{
		$ret = Array();

		foreach( $this->refrules as $cur)
		{
			if( isset($cur->owner) && $cur->owner !== null )
			{
				$class = get_class($cur->owner);
				//print $cur->owner->toString()."\n";
				if( $class == $type )
				{
					if( !in_array($cur->owner, $ret, TRUE) )
					{
						$ret[] = $cur->owner;
					}
				}
				
			}
		}
		
		return $ret;
	}
	
	
	public function generateRefHashComp($force=false)
	{
		if( $this->refcomphash !== null && !$force )
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

    public function getReferences()
    {
        return $this->refrules;
    }

    /**
     * @param string $className
     * @return array
     */
    public function & findReferencesWithClass($className)
    {
        $ret = Array();

        foreach($this->refrules as $reference)
        {
            if( get_class($reference) == $className )
                $ret[] = $reference;
        }

        return $ret;
    }
	
	
	public function name()
	{
		return $this->name;
	}
	
}
