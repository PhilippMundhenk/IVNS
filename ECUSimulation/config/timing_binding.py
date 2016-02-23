# .\timing_binding.py
# -*- coding: utf-8 -*-
# PyXB bindings for NM:b43a187ebbc2a19d7688cccc9f0bf73329ccfd18
# Generated 2015-03-30 16:31:40.632236 by PyXB version 1.2.4 using Python 3.4.1.final.0
# Namespace http://www.tum-create.edu.sg/timingSchema

from __future__ import unicode_literals
import pyxb.binding.saxer
import io
import pyxb.utils.utility
import pyxb.utils.domutils
import pyxb.utils.six as _six

# Unique identifier for bindings created at the same time
_GenerationUID = pyxb.utils.utility.UniqueIdentifier('urn:uuid:304c96c0-d6b7-11e4-9ae1-7845c42a7ad9')

# Version of PyXB used to generate the bindings
_PyXBVersion = '1.2.4'
# Generated bindings are not compatible across PyXB versions
if pyxb.__version__ != _PyXBVersion:
    raise pyxb.PyXBVersionError(_PyXBVersion)

# Import bindings for namespaces imported into schema
import pyxb.binding.datatypes

# NOTE: All namespace declarations are reserved within the binding
Namespace = pyxb.namespace.NamespaceForURI('http://www.tum-create.edu.sg/timingSchema', create_if_missing=True)
Namespace.configureCategories(['typeBinding', 'elementBinding'])

def CreateFromDocument (xml_text, default_namespace=None, location_base=None):
    """Parse the given XML and use the document element to create a
    Python instance.

    @param xml_text An XML document.  This should be data (Python 2
    str or Python 3 bytes), or a text (Python 2 unicode or Python 3
    str) in the L{pyxb._InputEncoding} encoding.

    @keyword default_namespace The L{pyxb.Namespace} instance to use as the
    default namespace where there is no default namespace in scope.
    If unspecified or C{None}, the namespace of the module containing
    this function will be used.

    @keyword location_base: An object to be recorded as the base of all
    L{pyxb.utils.utility.Location} instances associated with events and
    objects handled by the parser.  You might pass the URI from which
    the document was obtained.
    """

    if pyxb.XMLStyle_saxer != pyxb._XMLStyle:
        dom = pyxb.utils.domutils.StringToDOM(xml_text)
        return CreateFromDOM(dom.documentElement, default_namespace=default_namespace)
    if default_namespace is None:
        default_namespace = Namespace.fallbackNamespace()
    saxer = pyxb.binding.saxer.make_parser(fallback_namespace=default_namespace, location_base=location_base)
    handler = saxer.getContentHandler()
    xmld = xml_text
    if isinstance(xmld, _six.text_type):
        xmld = xmld.encode(pyxb._InputEncoding)
    saxer.parse(io.BytesIO(xmld))
    instance = handler.rootObject()
    return instance

def CreateFromDOM (node, default_namespace=None):
    """Create a Python instance from the given DOM node.
    The node tag must correspond to an element declaration in this module.

    @deprecated: Forcing use of DOM interface is unnecessary; use L{CreateFromDocument}."""
    if default_namespace is None:
        default_namespace = Namespace.fallbackNamespace()
    return pyxb.binding.basis.element.AnyCreateFromDOM(node, default_namespace)


# Complex type {http://www.tum-create.edu.sg/timingSchema}Timing with content type ELEMENT_ONLY
class Timing (pyxb.binding.basis.complexTypeDefinition):
    """Complex type {http://www.tum-create.edu.sg/timingSchema}Timing with content type ELEMENT_ONLY"""
    _TypeDefinition = None
    _ContentTypeTag = pyxb.binding.basis.complexTypeDefinition._CT_ELEMENT_ONLY
    _Abstract = False
    _ExpandedName = pyxb.namespace.ExpandedName(Namespace, 'Timing')
    _XSDLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 8, 4)
    _ElementMap = {}
    _AttributeMap = {}
    # Base type is pyxb.binding.datatypes.anyType
    
    # Element {http://www.tum-create.edu.sg/timingSchema}timingMappings uses Python identifier timingMappings
    __timingMappings = pyxb.binding.content.ElementDeclaration(pyxb.namespace.ExpandedName(Namespace, 'timingMappings'), 'timingMappings', '__httpwww_tum_create_edu_sgtimingSchema_Timing_httpwww_tum_create_edu_sgtimingSchematimingMappings', False, pyxb.utils.utility.Location('config\\timingSchema.xsd', 10, 6),)

    
    timingMappings = property(__timingMappings.value, __timingMappings.set, None, None)

    
    # Element {http://www.tum-create.edu.sg/timingSchema}dbLookups uses Python identifier dbLookups
    __dbLookups = pyxb.binding.content.ElementDeclaration(pyxb.namespace.ExpandedName(Namespace, 'dbLookups'), 'dbLookups', '__httpwww_tum_create_edu_sgtimingSchema_Timing_httpwww_tum_create_edu_sgtimingSchemadbLookups', False, pyxb.utils.utility.Location('config\\timingSchema.xsd', 11, 6),)

    
    dbLookups = property(__dbLookups.value, __dbLookups.set, None, None)

    _ElementMap.update({
        __timingMappings.name() : __timingMappings,
        __dbLookups.name() : __dbLookups
    })
    _AttributeMap.update({
        
    })
Namespace.addCategoryObject('typeBinding', 'Timing', Timing)


# Complex type {http://www.tum-create.edu.sg/timingSchema}TimingMappings with content type ELEMENT_ONLY
class TimingMappings (pyxb.binding.basis.complexTypeDefinition):
    """Complex type {http://www.tum-create.edu.sg/timingSchema}TimingMappings with content type ELEMENT_ONLY"""
    _TypeDefinition = None
    _ContentTypeTag = pyxb.binding.basis.complexTypeDefinition._CT_ELEMENT_ONLY
    _Abstract = False
    _ExpandedName = pyxb.namespace.ExpandedName(Namespace, 'TimingMappings')
    _XSDLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 15, 4)
    _ElementMap = {}
    _AttributeMap = {}
    # Base type is pyxb.binding.datatypes.anyType
    
    # Element {http://www.tum-create.edu.sg/timingSchema}timingMapping uses Python identifier timingMapping
    __timingMapping = pyxb.binding.content.ElementDeclaration(pyxb.namespace.ExpandedName(Namespace, 'timingMapping'), 'timingMapping', '__httpwww_tum_create_edu_sgtimingSchema_TimingMappings_httpwww_tum_create_edu_sgtimingSchematimingMapping', True, pyxb.utils.utility.Location('config\\timingSchema.xsd', 17, 6),)

    
    timingMapping = property(__timingMapping.value, __timingMapping.set, None, None)

    _ElementMap.update({
        __timingMapping.name() : __timingMapping
    })
    _AttributeMap.update({
        
    })
Namespace.addCategoryObject('typeBinding', 'TimingMappings', TimingMappings)


# Complex type {http://www.tum-create.edu.sg/timingSchema}DBLookups with content type ELEMENT_ONLY
class DBLookups (pyxb.binding.basis.complexTypeDefinition):
    """Complex type {http://www.tum-create.edu.sg/timingSchema}DBLookups with content type ELEMENT_ONLY"""
    _TypeDefinition = None
    _ContentTypeTag = pyxb.binding.basis.complexTypeDefinition._CT_ELEMENT_ONLY
    _Abstract = False
    _ExpandedName = pyxb.namespace.ExpandedName(Namespace, 'DBLookups')
    _XSDLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 23, 4)
    _ElementMap = {}
    _AttributeMap = {}
    # Base type is pyxb.binding.datatypes.anyType
    
    # Element {http://www.tum-create.edu.sg/timingSchema}dbLookup uses Python identifier dbLookup
    __dbLookup = pyxb.binding.content.ElementDeclaration(pyxb.namespace.ExpandedName(Namespace, 'dbLookup'), 'dbLookup', '__httpwww_tum_create_edu_sgtimingSchema_DBLookups_httpwww_tum_create_edu_sgtimingSchemadbLookup', True, pyxb.utils.utility.Location('config\\timingSchema.xsd', 25, 6),)

    
    dbLookup = property(__dbLookup.value, __dbLookup.set, None, None)

    _ElementMap.update({
        __dbLookup.name() : __dbLookup
    })
    _AttributeMap.update({
        
    })
Namespace.addCategoryObject('typeBinding', 'DBLookups', DBLookups)


# Complex type {http://www.tum-create.edu.sg/timingSchema}TimingMapping with content type ELEMENT_ONLY
class TimingMapping (pyxb.binding.basis.complexTypeDefinition):
    """Complex type {http://www.tum-create.edu.sg/timingSchema}TimingMapping with content type ELEMENT_ONLY"""
    _TypeDefinition = None
    _ContentTypeTag = pyxb.binding.basis.complexTypeDefinition._CT_ELEMENT_ONLY
    _Abstract = False
    _ExpandedName = pyxb.namespace.ExpandedName(Namespace, 'TimingMapping')
    _XSDLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 29, 4)
    _ElementMap = {}
    _AttributeMap = {}
    # Base type is pyxb.binding.datatypes.anyType
    
    # Element {http://www.tum-create.edu.sg/timingSchema}dbLookupSpecs uses Python identifier dbLookupSpecs
    __dbLookupSpecs = pyxb.binding.content.ElementDeclaration(pyxb.namespace.ExpandedName(Namespace, 'dbLookupSpecs'), 'dbLookupSpecs', '__httpwww_tum_create_edu_sgtimingSchema_TimingMapping_httpwww_tum_create_edu_sgtimingSchemadbLookupSpecs', False, pyxb.utils.utility.Location('config\\timingSchema.xsd', 31, 6),)

    
    dbLookupSpecs = property(__dbLookupSpecs.value, __dbLookupSpecs.set, None, None)

    
    # Element {http://www.tum-create.edu.sg/timingSchema}dbInterpolSpecs uses Python identifier dbInterpolSpecs
    __dbInterpolSpecs = pyxb.binding.content.ElementDeclaration(pyxb.namespace.ExpandedName(Namespace, 'dbInterpolSpecs'), 'dbInterpolSpecs', '__httpwww_tum_create_edu_sgtimingSchema_TimingMapping_httpwww_tum_create_edu_sgtimingSchemadbInterpolSpecs', False, pyxb.utils.utility.Location('config\\timingSchema.xsd', 32, 6),)

    
    dbInterpolSpecs = property(__dbInterpolSpecs.value, __dbInterpolSpecs.set, None, None)

    
    # Attribute name uses Python identifier name
    __name = pyxb.binding.content.AttributeUse(pyxb.namespace.ExpandedName(None, 'name'), 'name', '__httpwww_tum_create_edu_sgtimingSchema_TimingMapping_name', pyxb.binding.datatypes.string)
    __name._DeclarationLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 36, 5)
    __name._UseLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 36, 5)
    
    name = property(__name.value, __name.set, None, None)

    
    # Attribute class uses Python identifier class_
    __class = pyxb.binding.content.AttributeUse(pyxb.namespace.ExpandedName(None, 'class'), 'class_', '__httpwww_tum_create_edu_sgtimingSchema_TimingMapping_class', pyxb.binding.datatypes.string)
    __class._DeclarationLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 37, 5)
    __class._UseLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 37, 5)
    
    class_ = property(__class.value, __class.set, None, None)

    _ElementMap.update({
        __dbLookupSpecs.name() : __dbLookupSpecs,
        __dbInterpolSpecs.name() : __dbInterpolSpecs
    })
    _AttributeMap.update({
        __name.name() : __name,
        __class.name() : __class
    })
Namespace.addCategoryObject('typeBinding', 'TimingMapping', TimingMapping)


# Complex type {http://www.tum-create.edu.sg/timingSchema}DBLookupSpecs with content type ELEMENT_ONLY
class DBLookupSpecs (pyxb.binding.basis.complexTypeDefinition):
    """Complex type {http://www.tum-create.edu.sg/timingSchema}DBLookupSpecs with content type ELEMENT_ONLY"""
    _TypeDefinition = None
    _ContentTypeTag = pyxb.binding.basis.complexTypeDefinition._CT_ELEMENT_ONLY
    _Abstract = False
    _ExpandedName = pyxb.namespace.ExpandedName(Namespace, 'DBLookupSpecs')
    _XSDLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 41, 4)
    _ElementMap = {}
    _AttributeMap = {}
    # Base type is pyxb.binding.datatypes.anyType
    
    # Element {http://www.tum-create.edu.sg/timingSchema}dbLookupSpec uses Python identifier dbLookupSpec
    __dbLookupSpec = pyxb.binding.content.ElementDeclaration(pyxb.namespace.ExpandedName(Namespace, 'dbLookupSpec'), 'dbLookupSpec', '__httpwww_tum_create_edu_sgtimingSchema_DBLookupSpecs_httpwww_tum_create_edu_sgtimingSchemadbLookupSpec', True, pyxb.utils.utility.Location('config\\timingSchema.xsd', 43, 6),)

    
    dbLookupSpec = property(__dbLookupSpec.value, __dbLookupSpec.set, None, None)

    _ElementMap.update({
        __dbLookupSpec.name() : __dbLookupSpec
    })
    _AttributeMap.update({
        
    })
Namespace.addCategoryObject('typeBinding', 'DBLookupSpecs', DBLookupSpecs)


# Complex type {http://www.tum-create.edu.sg/timingSchema}DBLookupSpec with content type ELEMENT_ONLY
class DBLookupSpec (pyxb.binding.basis.complexTypeDefinition):
    """Complex type {http://www.tum-create.edu.sg/timingSchema}DBLookupSpec with content type ELEMENT_ONLY"""
    _TypeDefinition = None
    _ContentTypeTag = pyxb.binding.basis.complexTypeDefinition._CT_ELEMENT_ONLY
    _Abstract = False
    _ExpandedName = pyxb.namespace.ExpandedName(Namespace, 'DBLookupSpec')
    _XSDLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 47, 4)
    _ElementMap = {}
    _AttributeMap = {}
    # Base type is pyxb.binding.datatypes.anyType
    
    # Element {http://www.tum-create.edu.sg/timingSchema}variable uses Python identifier variable
    __variable = pyxb.binding.content.ElementDeclaration(pyxb.namespace.ExpandedName(Namespace, 'variable'), 'variable', '__httpwww_tum_create_edu_sgtimingSchema_DBLookupSpec_httpwww_tum_create_edu_sgtimingSchemavariable', True, pyxb.utils.utility.Location('config\\timingSchema.xsd', 49, 6),)

    
    variable = property(__variable.value, __variable.set, None, None)

    
    # Attribute id uses Python identifier id
    __id = pyxb.binding.content.AttributeUse(pyxb.namespace.ExpandedName(None, 'id'), 'id', '__httpwww_tum_create_edu_sgtimingSchema_DBLookupSpec_id', pyxb.binding.datatypes.string, required=True)
    __id._DeclarationLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 51, 5)
    __id._UseLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 51, 5)
    
    id = property(__id.value, __id.set, None, None)

    
    # Attribute dbpath uses Python identifier dbpath
    __dbpath = pyxb.binding.content.AttributeUse(pyxb.namespace.ExpandedName(None, 'dbpath'), 'dbpath', '__httpwww_tum_create_edu_sgtimingSchema_DBLookupSpec_dbpath', pyxb.binding.datatypes.string, required=True)
    __dbpath._DeclarationLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 52, 5)
    __dbpath._UseLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 52, 5)
    
    dbpath = property(__dbpath.value, __dbpath.set, None, None)

    
    # Attribute lookupid uses Python identifier lookupid
    __lookupid = pyxb.binding.content.AttributeUse(pyxb.namespace.ExpandedName(None, 'lookupid'), 'lookupid', '__httpwww_tum_create_edu_sgtimingSchema_DBLookupSpec_lookupid', pyxb.binding.datatypes.string, required=True)
    __lookupid._DeclarationLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 53, 5)
    __lookupid._UseLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 53, 5)
    
    lookupid = property(__lookupid.value, __lookupid.set, None, None)

    _ElementMap.update({
        __variable.name() : __variable
    })
    _AttributeMap.update({
        __id.name() : __id,
        __dbpath.name() : __dbpath,
        __lookupid.name() : __lookupid
    })
Namespace.addCategoryObject('typeBinding', 'DBLookupSpec', DBLookupSpec)


# Complex type {http://www.tum-create.edu.sg/timingSchema}DBInterpolSpecs with content type ELEMENT_ONLY
class DBInterpolSpecs (pyxb.binding.basis.complexTypeDefinition):
    """Complex type {http://www.tum-create.edu.sg/timingSchema}DBInterpolSpecs with content type ELEMENT_ONLY"""
    _TypeDefinition = None
    _ContentTypeTag = pyxb.binding.basis.complexTypeDefinition._CT_ELEMENT_ONLY
    _Abstract = False
    _ExpandedName = pyxb.namespace.ExpandedName(Namespace, 'DBInterpolSpecs')
    _XSDLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 56, 4)
    _ElementMap = {}
    _AttributeMap = {}
    # Base type is pyxb.binding.datatypes.anyType
    
    # Element {http://www.tum-create.edu.sg/timingSchema}dbInterpolationSpec uses Python identifier dbInterpolationSpec
    __dbInterpolationSpec = pyxb.binding.content.ElementDeclaration(pyxb.namespace.ExpandedName(Namespace, 'dbInterpolationSpec'), 'dbInterpolationSpec', '__httpwww_tum_create_edu_sgtimingSchema_DBInterpolSpecs_httpwww_tum_create_edu_sgtimingSchemadbInterpolationSpec', True, pyxb.utils.utility.Location('config\\timingSchema.xsd', 58, 6),)

    
    dbInterpolationSpec = property(__dbInterpolationSpec.value, __dbInterpolationSpec.set, None, None)

    _ElementMap.update({
        __dbInterpolationSpec.name() : __dbInterpolationSpec
    })
    _AttributeMap.update({
        
    })
Namespace.addCategoryObject('typeBinding', 'DBInterpolSpecs', DBInterpolSpecs)


# Complex type {http://www.tum-create.edu.sg/timingSchema}DBInterpolSpec with content type ELEMENT_ONLY
class DBInterpolSpec (pyxb.binding.basis.complexTypeDefinition):
    """Complex type {http://www.tum-create.edu.sg/timingSchema}DBInterpolSpec with content type ELEMENT_ONLY"""
    _TypeDefinition = None
    _ContentTypeTag = pyxb.binding.basis.complexTypeDefinition._CT_ELEMENT_ONLY
    _Abstract = False
    _ExpandedName = pyxb.namespace.ExpandedName(Namespace, 'DBInterpolSpec')
    _XSDLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 64, 4)
    _ElementMap = {}
    _AttributeMap = {}
    # Base type is pyxb.binding.datatypes.anyType
    
    # Element {http://www.tum-create.edu.sg/timingSchema}variable uses Python identifier variable
    __variable = pyxb.binding.content.ElementDeclaration(pyxb.namespace.ExpandedName(Namespace, 'variable'), 'variable', '__httpwww_tum_create_edu_sgtimingSchema_DBInterpolSpec_httpwww_tum_create_edu_sgtimingSchemavariable', True, pyxb.utils.utility.Location('config\\timingSchema.xsd', 66, 6),)

    
    variable = property(__variable.value, __variable.set, None, None)

    
    # Attribute id uses Python identifier id
    __id = pyxb.binding.content.AttributeUse(pyxb.namespace.ExpandedName(None, 'id'), 'id', '__httpwww_tum_create_edu_sgtimingSchema_DBInterpolSpec_id', pyxb.binding.datatypes.string, required=True)
    __id._DeclarationLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 68, 5)
    __id._UseLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 68, 5)
    
    id = property(__id.value, __id.set, None, None)

    
    # Attribute dbpath uses Python identifier dbpath
    __dbpath = pyxb.binding.content.AttributeUse(pyxb.namespace.ExpandedName(None, 'dbpath'), 'dbpath', '__httpwww_tum_create_edu_sgtimingSchema_DBInterpolSpec_dbpath', pyxb.binding.datatypes.string, required=True)
    __dbpath._DeclarationLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 69, 5)
    __dbpath._UseLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 69, 5)
    
    dbpath = property(__dbpath.value, __dbpath.set, None, None)

    
    # Attribute interpolmethod uses Python identifier interpolmethod
    __interpolmethod = pyxb.binding.content.AttributeUse(pyxb.namespace.ExpandedName(None, 'interpolmethod'), 'interpolmethod', '__httpwww_tum_create_edu_sgtimingSchema_DBInterpolSpec_interpolmethod', pyxb.binding.datatypes.string, required=True)
    __interpolmethod._DeclarationLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 70, 5)
    __interpolmethod._UseLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 70, 5)
    
    interpolmethod = property(__interpolmethod.value, __interpolmethod.set, None, None)

    
    # Attribute lookupid uses Python identifier lookupid
    __lookupid = pyxb.binding.content.AttributeUse(pyxb.namespace.ExpandedName(None, 'lookupid'), 'lookupid', '__httpwww_tum_create_edu_sgtimingSchema_DBInterpolSpec_lookupid', pyxb.binding.datatypes.string, required=True)
    __lookupid._DeclarationLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 71, 5)
    __lookupid._UseLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 71, 5)
    
    lookupid = property(__lookupid.value, __lookupid.set, None, None)

    _ElementMap.update({
        __variable.name() : __variable
    })
    _AttributeMap.update({
        __id.name() : __id,
        __dbpath.name() : __dbpath,
        __interpolmethod.name() : __interpolmethod,
        __lookupid.name() : __lookupid
    })
Namespace.addCategoryObject('typeBinding', 'DBInterpolSpec', DBInterpolSpec)


# Complex type {http://www.tum-create.edu.sg/timingSchema}Variable with content type ELEMENT_ONLY
class Variable (pyxb.binding.basis.complexTypeDefinition):
    """Complex type {http://www.tum-create.edu.sg/timingSchema}Variable with content type ELEMENT_ONLY"""
    _TypeDefinition = None
    _ContentTypeTag = pyxb.binding.basis.complexTypeDefinition._CT_ELEMENT_ONLY
    _Abstract = False
    _ExpandedName = pyxb.namespace.ExpandedName(Namespace, 'Variable')
    _XSDLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 74, 4)
    _ElementMap = {}
    _AttributeMap = {}
    # Base type is pyxb.binding.datatypes.anyType
    
    # Element {http://www.tum-create.edu.sg/timingSchema}value uses Python identifier value_
    __value = pyxb.binding.content.ElementDeclaration(pyxb.namespace.ExpandedName(Namespace, 'value'), 'value_', '__httpwww_tum_create_edu_sgtimingSchema_Variable_httpwww_tum_create_edu_sgtimingSchemavalue', False, pyxb.utils.utility.Location('config\\timingSchema.xsd', 76, 6),)

    
    value_ = property(__value.value, __value.set, None, None)

    
    # Attribute name uses Python identifier name
    __name = pyxb.binding.content.AttributeUse(pyxb.namespace.ExpandedName(None, 'name'), 'name', '__httpwww_tum_create_edu_sgtimingSchema_Variable_name', pyxb.binding.datatypes.string, required=True)
    __name._DeclarationLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 78, 5)
    __name._UseLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 78, 5)
    
    name = property(__name.value, __name.set, None, None)

    
    # Attribute type uses Python identifier type
    __type = pyxb.binding.content.AttributeUse(pyxb.namespace.ExpandedName(None, 'type'), 'type', '__httpwww_tum_create_edu_sgtimingSchema_Variable_type', pyxb.binding.datatypes.string, required=True)
    __type._DeclarationLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 79, 5)
    __type._UseLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 79, 5)
    
    type = property(__type.value, __type.set, None, None)

    
    # Attribute config uses Python identifier config
    __config = pyxb.binding.content.AttributeUse(pyxb.namespace.ExpandedName(None, 'config'), 'config', '__httpwww_tum_create_edu_sgtimingSchema_Variable_config', pyxb.binding.datatypes.string, required=True)
    __config._DeclarationLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 80, 5)
    __config._UseLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 80, 5)
    
    config = property(__config.value, __config.set, None, None)

    _ElementMap.update({
        __value.name() : __value
    })
    _AttributeMap.update({
        __name.name() : __name,
        __type.name() : __type,
        __config.name() : __config
    })
Namespace.addCategoryObject('typeBinding', 'Variable', Variable)


# Complex type {http://www.tum-create.edu.sg/timingSchema}DBLookup with content type ELEMENT_ONLY
class DBLookup (pyxb.binding.basis.complexTypeDefinition):
    """Complex type {http://www.tum-create.edu.sg/timingSchema}DBLookup with content type ELEMENT_ONLY"""
    _TypeDefinition = None
    _ContentTypeTag = pyxb.binding.basis.complexTypeDefinition._CT_ELEMENT_ONLY
    _Abstract = False
    _ExpandedName = pyxb.namespace.ExpandedName(Namespace, 'DBLookup')
    _XSDLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 83, 4)
    _ElementMap = {}
    _AttributeMap = {}
    # Base type is pyxb.binding.datatypes.anyType
    
    # Element {http://www.tum-create.edu.sg/timingSchema}dbLookupDesc uses Python identifier dbLookupDesc
    __dbLookupDesc = pyxb.binding.content.ElementDeclaration(pyxb.namespace.ExpandedName(Namespace, 'dbLookupDesc'), 'dbLookupDesc', '__httpwww_tum_create_edu_sgtimingSchema_DBLookup_httpwww_tum_create_edu_sgtimingSchemadbLookupDesc', False, pyxb.utils.utility.Location('config\\timingSchema.xsd', 85, 6),)

    
    dbLookupDesc = property(__dbLookupDesc.value, __dbLookupDesc.set, None, None)

    
    # Element {http://www.tum-create.edu.sg/timingSchema}dbLookupRequest uses Python identifier dbLookupRequest
    __dbLookupRequest = pyxb.binding.content.ElementDeclaration(pyxb.namespace.ExpandedName(Namespace, 'dbLookupRequest'), 'dbLookupRequest', '__httpwww_tum_create_edu_sgtimingSchema_DBLookup_httpwww_tum_create_edu_sgtimingSchemadbLookupRequest', False, pyxb.utils.utility.Location('config\\timingSchema.xsd', 86, 6),)

    
    dbLookupRequest = property(__dbLookupRequest.value, __dbLookupRequest.set, None, None)

    
    # Attribute id uses Python identifier id
    __id = pyxb.binding.content.AttributeUse(pyxb.namespace.ExpandedName(None, 'id'), 'id', '__httpwww_tum_create_edu_sgtimingSchema_DBLookup_id', pyxb.binding.datatypes.int)
    __id._DeclarationLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 90, 5)
    __id._UseLocation = pyxb.utils.utility.Location('config\\timingSchema.xsd', 90, 5)
    
    id = property(__id.value, __id.set, None, None)

    _ElementMap.update({
        __dbLookupDesc.name() : __dbLookupDesc,
        __dbLookupRequest.name() : __dbLookupRequest
    })
    _AttributeMap.update({
        __id.name() : __id
    })
Namespace.addCategoryObject('typeBinding', 'DBLookup', DBLookup)


dbLookupDesc = pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'dbLookupDesc'), pyxb.binding.datatypes.string, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 123, 4))
Namespace.addCategoryObject('elementBinding', dbLookupDesc.name().localName(), dbLookupDesc)

dbLookupRequest = pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'dbLookupRequest'), pyxb.binding.datatypes.string, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 125, 4))
Namespace.addCategoryObject('elementBinding', dbLookupRequest.name().localName(), dbLookupRequest)

timing = pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'timing'), Timing, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 107, 4))
Namespace.addCategoryObject('elementBinding', timing.name().localName(), timing)

timingMappings = pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'timingMappings'), TimingMappings, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 111, 4))
Namespace.addCategoryObject('elementBinding', timingMappings.name().localName(), timingMappings)

timingMapping = pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'timingMapping'), TimingMapping, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 113, 4))
Namespace.addCategoryObject('elementBinding', timingMapping.name().localName(), timingMapping)

dbLookupSpec = pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'dbLookupSpec'), DBLookupSpec, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 115, 4))
Namespace.addCategoryObject('elementBinding', dbLookupSpec.name().localName(), dbLookupSpec)

dbInterpolSpec = pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'dbInterpolSpec'), DBInterpolSpec, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 117, 4))
Namespace.addCategoryObject('elementBinding', dbInterpolSpec.name().localName(), dbInterpolSpec)

dbInterpolSpecs = pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'dbInterpolSpecs'), DBInterpolSpecs, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 119, 4))
Namespace.addCategoryObject('elementBinding', dbInterpolSpecs.name().localName(), dbInterpolSpecs)

dbLookup = pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'dbLookup'), DBLookup, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 121, 4))
Namespace.addCategoryObject('elementBinding', dbLookup.name().localName(), dbLookup)

dbLookups = pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'dbLookups'), DBLookups, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 127, 4))
Namespace.addCategoryObject('elementBinding', dbLookups.name().localName(), dbLookups)

dbLookupSpecs = pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'dbLookupSpecs'), DBLookupSpecs, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 129, 4))
Namespace.addCategoryObject('elementBinding', dbLookupSpecs.name().localName(), dbLookupSpecs)

variable = pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'variable'), Variable, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 131, 4))
Namespace.addCategoryObject('elementBinding', variable.name().localName(), variable)



Timing._AddElement(pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'timingMappings'), TimingMappings, scope=Timing, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 10, 6)))

Timing._AddElement(pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'dbLookups'), DBLookups, scope=Timing, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 11, 6)))

def _BuildAutomaton ():
    # Remove this helper function from the namespace after it is invoked
    global _BuildAutomaton
    del _BuildAutomaton
    import pyxb.utils.fac as fac

    counters = set()
    states = []
    final_update = None
    symbol = pyxb.binding.content.ElementUse(Timing._UseForTag(pyxb.namespace.ExpandedName(Namespace, 'timingMappings')), pyxb.utils.utility.Location('config\\timingSchema.xsd', 10, 6))
    st_0 = fac.State(symbol, is_initial=True, final_update=final_update, is_unordered_catenation=False)
    states.append(st_0)
    final_update = set()
    symbol = pyxb.binding.content.ElementUse(Timing._UseForTag(pyxb.namespace.ExpandedName(Namespace, 'dbLookups')), pyxb.utils.utility.Location('config\\timingSchema.xsd', 11, 6))
    st_1 = fac.State(symbol, is_initial=False, final_update=final_update, is_unordered_catenation=False)
    states.append(st_1)
    transitions = []
    transitions.append(fac.Transition(st_1, [
         ]))
    st_0._set_transitionSet(transitions)
    transitions = []
    st_1._set_transitionSet(transitions)
    return fac.Automaton(states, counters, False, containing_state=None)
Timing._Automaton = _BuildAutomaton()




TimingMappings._AddElement(pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'timingMapping'), TimingMapping, scope=TimingMappings, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 17, 6)))

def _BuildAutomaton_ ():
    # Remove this helper function from the namespace after it is invoked
    global _BuildAutomaton_
    del _BuildAutomaton_
    import pyxb.utils.fac as fac

    counters = set()
    cc_0 = fac.CounterCondition(min=0, max=None, metadata=pyxb.utils.utility.Location('config\\timingSchema.xsd', 17, 6))
    counters.add(cc_0)
    states = []
    final_update = set()
    final_update.add(fac.UpdateInstruction(cc_0, False))
    symbol = pyxb.binding.content.ElementUse(TimingMappings._UseForTag(pyxb.namespace.ExpandedName(Namespace, 'timingMapping')), pyxb.utils.utility.Location('config\\timingSchema.xsd', 17, 6))
    st_0 = fac.State(symbol, is_initial=True, final_update=final_update, is_unordered_catenation=False)
    states.append(st_0)
    transitions = []
    transitions.append(fac.Transition(st_0, [
        fac.UpdateInstruction(cc_0, True) ]))
    st_0._set_transitionSet(transitions)
    return fac.Automaton(states, counters, True, containing_state=None)
TimingMappings._Automaton = _BuildAutomaton_()




DBLookups._AddElement(pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'dbLookup'), DBLookup, scope=DBLookups, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 25, 6)))

def _BuildAutomaton_2 ():
    # Remove this helper function from the namespace after it is invoked
    global _BuildAutomaton_2
    del _BuildAutomaton_2
    import pyxb.utils.fac as fac

    counters = set()
    cc_0 = fac.CounterCondition(min=0, max=None, metadata=pyxb.utils.utility.Location('config\\timingSchema.xsd', 25, 6))
    counters.add(cc_0)
    states = []
    final_update = set()
    final_update.add(fac.UpdateInstruction(cc_0, False))
    symbol = pyxb.binding.content.ElementUse(DBLookups._UseForTag(pyxb.namespace.ExpandedName(Namespace, 'dbLookup')), pyxb.utils.utility.Location('config\\timingSchema.xsd', 25, 6))
    st_0 = fac.State(symbol, is_initial=True, final_update=final_update, is_unordered_catenation=False)
    states.append(st_0)
    transitions = []
    transitions.append(fac.Transition(st_0, [
        fac.UpdateInstruction(cc_0, True) ]))
    st_0._set_transitionSet(transitions)
    return fac.Automaton(states, counters, True, containing_state=None)
DBLookups._Automaton = _BuildAutomaton_2()




TimingMapping._AddElement(pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'dbLookupSpecs'), DBLookupSpecs, scope=TimingMapping, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 31, 6)))

TimingMapping._AddElement(pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'dbInterpolSpecs'), DBInterpolSpecs, scope=TimingMapping, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 32, 6)))

def _BuildAutomaton_3 ():
    # Remove this helper function from the namespace after it is invoked
    global _BuildAutomaton_3
    del _BuildAutomaton_3
    import pyxb.utils.fac as fac

    counters = set()
    states = []
    final_update = None
    symbol = pyxb.binding.content.ElementUse(TimingMapping._UseForTag(pyxb.namespace.ExpandedName(Namespace, 'dbLookupSpecs')), pyxb.utils.utility.Location('config\\timingSchema.xsd', 31, 6))
    st_0 = fac.State(symbol, is_initial=True, final_update=final_update, is_unordered_catenation=False)
    states.append(st_0)
    final_update = set()
    symbol = pyxb.binding.content.ElementUse(TimingMapping._UseForTag(pyxb.namespace.ExpandedName(Namespace, 'dbInterpolSpecs')), pyxb.utils.utility.Location('config\\timingSchema.xsd', 32, 6))
    st_1 = fac.State(symbol, is_initial=False, final_update=final_update, is_unordered_catenation=False)
    states.append(st_1)
    transitions = []
    transitions.append(fac.Transition(st_1, [
         ]))
    st_0._set_transitionSet(transitions)
    transitions = []
    st_1._set_transitionSet(transitions)
    return fac.Automaton(states, counters, False, containing_state=None)
TimingMapping._Automaton = _BuildAutomaton_3()




DBLookupSpecs._AddElement(pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'dbLookupSpec'), DBLookupSpec, scope=DBLookupSpecs, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 43, 6)))

def _BuildAutomaton_4 ():
    # Remove this helper function from the namespace after it is invoked
    global _BuildAutomaton_4
    del _BuildAutomaton_4
    import pyxb.utils.fac as fac

    counters = set()
    cc_0 = fac.CounterCondition(min=0, max=None, metadata=pyxb.utils.utility.Location('config\\timingSchema.xsd', 43, 6))
    counters.add(cc_0)
    states = []
    final_update = set()
    final_update.add(fac.UpdateInstruction(cc_0, False))
    symbol = pyxb.binding.content.ElementUse(DBLookupSpecs._UseForTag(pyxb.namespace.ExpandedName(Namespace, 'dbLookupSpec')), pyxb.utils.utility.Location('config\\timingSchema.xsd', 43, 6))
    st_0 = fac.State(symbol, is_initial=True, final_update=final_update, is_unordered_catenation=False)
    states.append(st_0)
    transitions = []
    transitions.append(fac.Transition(st_0, [
        fac.UpdateInstruction(cc_0, True) ]))
    st_0._set_transitionSet(transitions)
    return fac.Automaton(states, counters, True, containing_state=None)
DBLookupSpecs._Automaton = _BuildAutomaton_4()




DBLookupSpec._AddElement(pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'variable'), Variable, scope=DBLookupSpec, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 49, 6)))

def _BuildAutomaton_5 ():
    # Remove this helper function from the namespace after it is invoked
    global _BuildAutomaton_5
    del _BuildAutomaton_5
    import pyxb.utils.fac as fac

    counters = set()
    states = []
    final_update = set()
    symbol = pyxb.binding.content.ElementUse(DBLookupSpec._UseForTag(pyxb.namespace.ExpandedName(Namespace, 'variable')), pyxb.utils.utility.Location('config\\timingSchema.xsd', 49, 6))
    st_0 = fac.State(symbol, is_initial=True, final_update=final_update, is_unordered_catenation=False)
    states.append(st_0)
    transitions = []
    transitions.append(fac.Transition(st_0, [
         ]))
    st_0._set_transitionSet(transitions)
    return fac.Automaton(states, counters, False, containing_state=None)
DBLookupSpec._Automaton = _BuildAutomaton_5()




DBInterpolSpecs._AddElement(pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'dbInterpolationSpec'), DBInterpolSpec, scope=DBInterpolSpecs, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 58, 6)))

def _BuildAutomaton_6 ():
    # Remove this helper function from the namespace after it is invoked
    global _BuildAutomaton_6
    del _BuildAutomaton_6
    import pyxb.utils.fac as fac

    counters = set()
    cc_0 = fac.CounterCondition(min=0, max=None, metadata=pyxb.utils.utility.Location('config\\timingSchema.xsd', 58, 6))
    counters.add(cc_0)
    states = []
    final_update = set()
    final_update.add(fac.UpdateInstruction(cc_0, False))
    symbol = pyxb.binding.content.ElementUse(DBInterpolSpecs._UseForTag(pyxb.namespace.ExpandedName(Namespace, 'dbInterpolationSpec')), pyxb.utils.utility.Location('config\\timingSchema.xsd', 58, 6))
    st_0 = fac.State(symbol, is_initial=True, final_update=final_update, is_unordered_catenation=False)
    states.append(st_0)
    transitions = []
    transitions.append(fac.Transition(st_0, [
        fac.UpdateInstruction(cc_0, True) ]))
    st_0._set_transitionSet(transitions)
    return fac.Automaton(states, counters, True, containing_state=None)
DBInterpolSpecs._Automaton = _BuildAutomaton_6()




DBInterpolSpec._AddElement(pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'variable'), Variable, scope=DBInterpolSpec, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 66, 6)))

def _BuildAutomaton_7 ():
    # Remove this helper function from the namespace after it is invoked
    global _BuildAutomaton_7
    del _BuildAutomaton_7
    import pyxb.utils.fac as fac

    counters = set()
    states = []
    final_update = set()
    symbol = pyxb.binding.content.ElementUse(DBInterpolSpec._UseForTag(pyxb.namespace.ExpandedName(Namespace, 'variable')), pyxb.utils.utility.Location('config\\timingSchema.xsd', 66, 6))
    st_0 = fac.State(symbol, is_initial=True, final_update=final_update, is_unordered_catenation=False)
    states.append(st_0)
    transitions = []
    transitions.append(fac.Transition(st_0, [
         ]))
    st_0._set_transitionSet(transitions)
    return fac.Automaton(states, counters, False, containing_state=None)
DBInterpolSpec._Automaton = _BuildAutomaton_7()




Variable._AddElement(pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'value'), pyxb.binding.datatypes.string, scope=Variable, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 76, 6)))

def _BuildAutomaton_8 ():
    # Remove this helper function from the namespace after it is invoked
    global _BuildAutomaton_8
    del _BuildAutomaton_8
    import pyxb.utils.fac as fac

    counters = set()
    states = []
    final_update = set()
    symbol = pyxb.binding.content.ElementUse(Variable._UseForTag(pyxb.namespace.ExpandedName(Namespace, 'value')), pyxb.utils.utility.Location('config\\timingSchema.xsd', 76, 6))
    st_0 = fac.State(symbol, is_initial=True, final_update=final_update, is_unordered_catenation=False)
    states.append(st_0)
    transitions = []
    st_0._set_transitionSet(transitions)
    return fac.Automaton(states, counters, False, containing_state=None)
Variable._Automaton = _BuildAutomaton_8()




DBLookup._AddElement(pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'dbLookupDesc'), pyxb.binding.datatypes.string, scope=DBLookup, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 85, 6)))

DBLookup._AddElement(pyxb.binding.basis.element(pyxb.namespace.ExpandedName(Namespace, 'dbLookupRequest'), pyxb.binding.datatypes.string, scope=DBLookup, location=pyxb.utils.utility.Location('config\\timingSchema.xsd', 86, 6)))

def _BuildAutomaton_9 ():
    # Remove this helper function from the namespace after it is invoked
    global _BuildAutomaton_9
    del _BuildAutomaton_9
    import pyxb.utils.fac as fac

    counters = set()
    states = []
    final_update = None
    symbol = pyxb.binding.content.ElementUse(DBLookup._UseForTag(pyxb.namespace.ExpandedName(Namespace, 'dbLookupDesc')), pyxb.utils.utility.Location('config\\timingSchema.xsd', 85, 6))
    st_0 = fac.State(symbol, is_initial=True, final_update=final_update, is_unordered_catenation=False)
    states.append(st_0)
    final_update = set()
    symbol = pyxb.binding.content.ElementUse(DBLookup._UseForTag(pyxb.namespace.ExpandedName(Namespace, 'dbLookupRequest')), pyxb.utils.utility.Location('config\\timingSchema.xsd', 86, 6))
    st_1 = fac.State(symbol, is_initial=False, final_update=final_update, is_unordered_catenation=False)
    states.append(st_1)
    transitions = []
    transitions.append(fac.Transition(st_1, [
         ]))
    st_0._set_transitionSet(transitions)
    transitions = []
    st_1._set_transitionSet(transitions)
    return fac.Automaton(states, counters, False, containing_state=None)
DBLookup._Automaton = _BuildAutomaton_9()

