<?php

class DH
{
	static function Hosts_to_xmlDom(DOMNode $a, &$objects, $tagName = 'member', $showAnyIfZero=true)
	{
		//print_r($a);
		
		while( $a->hasChildNodes() )
			$a->removeChild($a->childNodes->item(0));
		
		$c = count($objects);
		if( $c == 0 && $showAnyIfZero == true)
		{
			$tmp = $a->ownerDocument->createElement($tagName);
			$tmp = $a->appendChild($tmp);
			$tmp->appendChild( $a->ownerDocument->createTextNode('any') );
			return;
		}
		
		foreach( $objects as $o )
		{
			$tmp = $a->ownerDocument->createElement($tagName);
			$tmp = $a->appendChild($tmp);
			$tmp->appendChild( $a->ownerDocument->createTextNode($o->name()) );
		}
		//print_r($a);
	}

	static function setDomNodeText(DOMNode $node, $text)
	{
		DH::clearDomNodeChilds($node);
		$node->appendChild( $node->ownerDocument->createTextNode($text) );
	}

    static function makeElementAsRoot(DOMElement $newRoot, DOMNode $doc)
    {
        $doc->appendChild($newRoot);

        $nodes = Array();
        foreach( $doc->childNodes as $node )
        {
            $nodes[] = $node;
        }

        foreach( $nodes as $node )
        {
            if( !$newRoot->isSameNode($node) )
                $doc->removeChild($node);
        }

    }

	static function removeReplaceElement( DOMElement $el, $newName )
	{
		$ret = $el->ownerDocument->createElement($newName);
		$ret= $el->parentNode->replaceChild($ret, $el);

		return $ret;
	}

	static function clearDomNodeChilds(DOMNode $node)
	{
		while( $node->hasChildNodes() )
			$node->removeChild($node->childNodes->item(0));
	}

	static function firstChildElement(DOMNode $node)
	{
		foreach( $node->childNodes as $child )
		{
			if( $child->nodeType == 1 )
				return $child;
		}

		return FALSE;
	}

	static function findFirstElementOrDie($tagName, DOMNode $node)
	{
		$ret = DH::findFirstElement($tagName, $node);

		if( $ret === FALSE )
			derr(' xml element <'.$tagName.'> was not found');

		return $ret;
	}

    /**
     * @param $tagName
     * @param DOMNode $node
     * @return bool|DOMNode
     */
	static function findFirstElement($tagName, DOMNode $node)
	{
		foreach( $node->childNodes as $lnode )
		{
			if( $lnode->nodeName == $tagName )
				return $lnode;
		}

		return FALSE;
	}

	static function removeChild(DOMNode $parent, DOMNode $child)
	{
		if( $child->parentNode === $parent )
		{
			$parent->removeChild($child);
		}
	}

	static function createElement(DOMNode $parent,$tagName, $withText = null)
	{
		$ret = $parent->ownerDocument->createElement($tagName);
		$ret = $parent->appendChild($ret);
		if( !is_null($withText) )
		{
			$tmp = $parent->ownerDocument->createTextNode($withText);
			$ret->appendChild($tmp);
		}

		return $ret;
	}

    /**
     * @param string $tagName
     * @param DOMNode $node
     * @param null|string $withText
     * @return bool|DOMElement|DOMNode
     */
	static function findFirstElementOrCreate($tagName, DOMNode $node, $withText = null)
	{
		$ret = DH::findFirstElement($tagName, $node);

		if( $ret === FALSE )
		{
			return DH::createElement($node, $tagName, $withText);
		}

		return $ret;
	}

    /**
     * @param string $tagName
     * @param $value
     * @param DOMNode $node
     * @return DOMNode|bool
     */
	static function findFirstElementByNameAttrOrDie($tagName, $value, DOMNode $node)
	{
		foreach( $node->childNodes as $lnode )
		{
			if( $lnode->nodeName == $tagName )
			{
				$attr = $lnode->attributes->getNamedItem('name');
				if( !is_null($attr) )
				{
					if( $attr->nodeValue == $value )
					return $lnode;
				}
			}
		}

		derr(' xml element <'.$tagName.' name="'.$value.'"> was not found');
        return FALSE;
	}

    /**
     * @param $attrName
     * @param DOMElement|DOMNode $node
     * @return bool|string
     */
	static function findAttribute($attrName, DOMElement $node)
	{

		foreach( $node->attributes as $child )
		{
			if( $child->nodeName == $attrName )
			{
				return $child->nodeValue;
			}
		}

		return FALSE;
	}

    /**
     * @param DOMNode $node
     * @param int $indenting
     * @param bool $lineReturn
     * @param int $limitSubLevels
     * @return string
     */
	static function &dom_to_xml(DOMNode $node, $indenting = 0, $lineReturn = true, $limitSubLevels = -1)
	{
		$ind = '';
		$out = '';

        if( $limitSubLevels >= 0 && $limitSubLevels == $indenting )
            return $ind;

        $ind = str_pad('', $indenting, ' ');
		
		$firstTag = $ind.'<'.$node->nodeName;

        if( get_class($node) != 'DOMDocument' )
            foreach($node->attributes as $at)
            {
                $firstTag .= ' '.$at->name.'="'.$at->value.'"';
            }
		
		//$firsttag .= '>';
		
		$c = 0;
		$wroteChildren = false;
		
		$tmpout = '';
		
		if( DH::firstChildElement($node) !== FALSE )
		{
			foreach( $node->childNodes as $n)
			{
				if( $n->nodeType != 1 ) continue;

				if( $indenting != -1 )
					$tmpout .= DH::dom_to_xml($n, $indenting + 1,$lineReturn, $limitSubLevels);
				else
					$tmpout .= DH::dom_to_xml($n, -1, $lineReturn, $limitSubLevels);
				$wroteChildren = true;
			}
		}

			
		if( $wroteChildren == false )
		{

			if( DH::firstChildElement($node) !== FALSE || is_null($node->textContent) || strlen($node->textContent) < 1 )
			{
				if( $lineReturn )
					$out .= $firstTag."/>\n";
				else
					$out .= $firstTag."/>";
			}
			else
			{
				if( $lineReturn )
					$out .= $firstTag.'>'.$node->textContent.'</'.$node->nodeName.">\n";
				else
					$out .= $firstTag.'>'.$node->textContent.'</'.$node->nodeName.">";
			}
		}
		else
		{
			if( $lineReturn )
				$out .= $firstTag.">\n".$tmpout.$ind.'</'.$node->nodeName.">\n";
			else
				$out .= $firstTag.">".$tmpout.$ind.'</'.$node->nodeName.">";
		}

		return $out;	
	}
}

