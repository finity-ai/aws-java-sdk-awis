//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.11 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2015.08.26 at 01:55:20 PM PDT 
//


package net.distributary.tahseen.awis.generated;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.CollapsedStringAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;


/**
 * Structure containing information directly related to a site's usage (such as categories and related links)
 * 
 * <p>Java class for RelatedType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="RelatedType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;extension base="{http://alexa.amazonaws.com/doc/2005-10-05/}UrlServiceType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="RelatedLinks" minOccurs="0"&gt;
 *           &lt;complexType&gt;
 *             &lt;complexContent&gt;
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                 &lt;sequence&gt;
 *                   &lt;element name="RelatedLink" type="{http://alexa.amazonaws.com/doc/2005-10-05/}RelatedLinkType" maxOccurs="unbounded"/&gt;
 *                 &lt;/sequence&gt;
 *               &lt;/restriction&gt;
 *             &lt;/complexContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *         &lt;element name="Categories" minOccurs="0"&gt;
 *           &lt;complexType&gt;
 *             &lt;complexContent&gt;
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                 &lt;sequence&gt;
 *                   &lt;element name="CategoryData" maxOccurs="unbounded"&gt;
 *                     &lt;complexType&gt;
 *                       &lt;complexContent&gt;
 *                         &lt;extension base="{http://alexa.amazonaws.com/doc/2005-10-05/}CategoryType"&gt;
 *                           &lt;sequence&gt;
 *                             &lt;element name="AbsolutePath" type="{http://www.w3.org/2001/XMLSchema}token"/&gt;
 *                           &lt;/sequence&gt;
 *                         &lt;/extension&gt;
 *                       &lt;/complexContent&gt;
 *                     &lt;/complexType&gt;
 *                   &lt;/element&gt;
 *                 &lt;/sequence&gt;
 *               &lt;/restriction&gt;
 *             &lt;/complexContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *       &lt;/sequence&gt;
 *     &lt;/extension&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "RelatedType", propOrder = {
    "relatedLinks",
    "categories"
})
public class RelatedType
    extends UrlServiceType
{

    @XmlElement(name = "RelatedLinks")
    protected RelatedType.RelatedLinks relatedLinks;
    @XmlElement(name = "Categories")
    protected RelatedType.Categories categories;

    /**
     * Gets the value of the relatedLinks property.
     * 
     * @return
     *     possible object is
     *     {@link RelatedType.RelatedLinks }
     *     
     */
    public RelatedType.RelatedLinks getRelatedLinks() {
        return relatedLinks;
    }

    /**
     * Sets the value of the relatedLinks property.
     * 
     * @param value
     *     allowed object is
     *     {@link RelatedType.RelatedLinks }
     *     
     */
    public void setRelatedLinks(RelatedType.RelatedLinks value) {
        this.relatedLinks = value;
    }

    /**
     * Gets the value of the categories property.
     * 
     * @return
     *     possible object is
     *     {@link RelatedType.Categories }
     *     
     */
    public RelatedType.Categories getCategories() {
        return categories;
    }

    /**
     * Sets the value of the categories property.
     * 
     * @param value
     *     allowed object is
     *     {@link RelatedType.Categories }
     *     
     */
    public void setCategories(RelatedType.Categories value) {
        this.categories = value;
    }


    /**
     * <p>Java class for anonymous complex type.
     * 
     * <p>The following schema fragment specifies the expected content contained within this class.
     * 
     * <pre>
     * &lt;complexType&gt;
     *   &lt;complexContent&gt;
     *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
     *       &lt;sequence&gt;
     *         &lt;element name="CategoryData" maxOccurs="unbounded"&gt;
     *           &lt;complexType&gt;
     *             &lt;complexContent&gt;
     *               &lt;extension base="{http://alexa.amazonaws.com/doc/2005-10-05/}CategoryType"&gt;
     *                 &lt;sequence&gt;
     *                   &lt;element name="AbsolutePath" type="{http://www.w3.org/2001/XMLSchema}token"/&gt;
     *                 &lt;/sequence&gt;
     *               &lt;/extension&gt;
     *             &lt;/complexContent&gt;
     *           &lt;/complexType&gt;
     *         &lt;/element&gt;
     *       &lt;/sequence&gt;
     *     &lt;/restriction&gt;
     *   &lt;/complexContent&gt;
     * &lt;/complexType&gt;
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "categoryData"
    })
    public static class Categories {

        @XmlElement(name = "CategoryData", required = true)
        protected List<RelatedType.Categories.CategoryData> categoryData;

        /**
         * Gets the value of the categoryData property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the categoryData property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getCategoryData().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link RelatedType.Categories.CategoryData }
         * 
         * 
         */
        public List<RelatedType.Categories.CategoryData> getCategoryData() {
            if (categoryData == null) {
                categoryData = new ArrayList<RelatedType.Categories.CategoryData>();
            }
            return this.categoryData;
        }


        /**
         * <p>Java class for anonymous complex type.
         * 
         * <p>The following schema fragment specifies the expected content contained within this class.
         * 
         * <pre>
         * &lt;complexType&gt;
         *   &lt;complexContent&gt;
         *     &lt;extension base="{http://alexa.amazonaws.com/doc/2005-10-05/}CategoryType"&gt;
         *       &lt;sequence&gt;
         *         &lt;element name="AbsolutePath" type="{http://www.w3.org/2001/XMLSchema}token"/&gt;
         *       &lt;/sequence&gt;
         *     &lt;/extension&gt;
         *   &lt;/complexContent&gt;
         * &lt;/complexType&gt;
         * </pre>
         * 
         * 
         */
        @XmlAccessorType(XmlAccessType.FIELD)
        @XmlType(name = "", propOrder = {
            "absolutePath"
        })
        public static class CategoryData
            extends CategoryType
        {

            @XmlElement(name = "AbsolutePath", required = true)
            @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
            @XmlSchemaType(name = "token")
            protected String absolutePath;

            /**
             * Gets the value of the absolutePath property.
             * 
             * @return
             *     possible object is
             *     {@link String }
             *     
             */
            public String getAbsolutePath() {
                return absolutePath;
            }

            /**
             * Sets the value of the absolutePath property.
             * 
             * @param value
             *     allowed object is
             *     {@link String }
             *     
             */
            public void setAbsolutePath(String value) {
                this.absolutePath = value;
            }

        }

    }


    /**
     * <p>Java class for anonymous complex type.
     * 
     * <p>The following schema fragment specifies the expected content contained within this class.
     * 
     * <pre>
     * &lt;complexType&gt;
     *   &lt;complexContent&gt;
     *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
     *       &lt;sequence&gt;
     *         &lt;element name="RelatedLink" type="{http://alexa.amazonaws.com/doc/2005-10-05/}RelatedLinkType" maxOccurs="unbounded"/&gt;
     *       &lt;/sequence&gt;
     *     &lt;/restriction&gt;
     *   &lt;/complexContent&gt;
     * &lt;/complexType&gt;
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "relatedLink"
    })
    public static class RelatedLinks {

        @XmlElement(name = "RelatedLink", required = true)
        protected List<RelatedLinkType> relatedLink;

        /**
         * Gets the value of the relatedLink property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the relatedLink property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getRelatedLink().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link RelatedLinkType }
         * 
         * 
         */
        public List<RelatedLinkType> getRelatedLink() {
            if (relatedLink == null) {
                relatedLink = new ArrayList<RelatedLinkType>();
            }
            return this.relatedLink;
        }

    }

}